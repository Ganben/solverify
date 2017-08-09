#encoding=utf-8
# ganben
# this is the class file which defines verification needed vars and funcs and checking processes

from z3 import *
import logging
import varprepares as vp
import midprocess as mp
import preprocess as pp
import global_params

class Verifier():
    """
    constructor: id;
    init process: init with sol, init with bytecode, init with opcode or other processed vars
    checker: every checker is a single function, must perform after success init
    output parameter: results
    returns for certain type check: result
    a centralized method to perform all checkers
    """
    def __init__(self):
        """prepare all vars"""
        # load source files
        self.sol = None
        self.evm = None
        self.disasm_raw = None
        self.disasm = None
        self.opcode = None
        self.is_loaded = False
        # symbolic exec

        self.block = 0
        self.pre_block = 0
        self.visited =[]
        self.depth = 0
        self.stack = []
        self.mem = {}
        self.memory = []  # This memory is used only for the process of finding the position of a mapping
        #  variable in storage. In this process, memory is used for hashing methods

        g_state, in_state = vp.init_global_state()
        path_conditions_and_vars, g_state = vp.generate_defaults(g_state, in_state)

        self.global_state = g_state
        self.path_conditions_and_vars = path_conditions_and_vars
        self.analysis = vp.init_analysis()
        self.path = []
        self.models = []

        self.solver = Solver()
        self.solver.set("timeout", global_params.TIMEOUT)

        self.visited_edges = {}
        self.money_flow_all_paths = []
        self.data_flow_all_paths = [[], []]
        self.path_conditions = []
        self.all_gs =[]
        self.results = {}
        self.log = logging.getLogger(__name__)
        # sym_exec_block(block, pre_block, visited, depth, stack, mem, memory, global_state, path_conditions_and_vars,
        #               analysis, path, models):
        # global solver
        # global visited_edges
        # global money_flow_all_paths
        # global data_flow_all_paths
        # global path_conditions
        # global all_gs
        # global results
        self.Edge = namedtuple("Edge", ["v1", "v2"])  # Factory Function for tuples is used as dictionary key

        self.reentrancy_all_paths = []

        if global_params.USE_GLOBAL_BLOCKCHAIN:
            self.data_source = EthereumData()

    def compile(self):
        """this func exec compile and prepare script, read and fill self attrs
        :param: None
        :returns: True/False/Exceptions
        """
        if self.is_loaded:
            if not self.evm:
                _, _, eres = pp.sol2evm(self.sol)
                self.evm = eres[0]  #no need list, if so need depre sol input; :TODO: warn multi
            try:

                self.disasm_raw = pp.evm2opcode(self.evm)

                self.disasm, self.tokens = mp.construction_var(self.disasm_raw)  #TODO: check call type

                self.end_ins_dict, self.instructions, self.jump_type = mp.cons_token2vertices(self.tokens)

                self.vertices, self.edges = mp.cons_basicblock(self.end_ins_dict, self.instructions, self.jump_type)

                self.vertices, self.edges = mp.cons_static_edges(self.jump_type, self.vertices, self.edges)

            except Exception as e:
                self.log.error(' verifier compile error: %s ' % e)
                raise

        else:
            raise ValueError('Not Loaded')


    def load_sol(self, sol):
        """load a solidity source code, pass in a solidity code
        :param: source code text, multi lines
        :returns: True/Error
        """
        if not self.is_loaded:
            self.sol = sol
            self.is_loaded = True
            return True
        else:
            raise BaseException('Already Loaded')


    def load_byte(self, evmcode):
        """load a evm source code, pass in a bytecode string
        :param: bytecode evm, single line
        :returns: True/Error
        """
        if not self.is_loaded:
            self.evm = evmcode
            self.is_loaded = True
            return True
        else:
            raise BaseException('Already Loaded')


    def check_all(self):
        """this func call all check items"""

        if self.is_loaded:
            try:
                self.compile()
            except Exception as e:
                self.log.error(e)
                raise
            # try every check items
            try:
                self.check_callstack_attack()
                self.sym_exec_block()

        else:
            raise BaseException('Load source first')


    def check_callstack_attack(self):
        """check callstack bug
        :param: self.disasm
        :returns: results['callstack'] = True/False
        """
        if self.disasm:
            try:
                r = vp.run_callstack_attack(self.disasm)
                self.results['callstack'] = r['callstack']
            except Exception as e:
                self.log.error(e)
                return None
            return self.results.get('callstack', True)
        else:
            raise ValueError('No disasm code found')

    def sym_exec_block(self):
        """symbol execution run and simulation
        :param: None but read attr
        :returns: None but update results {}"""
        # pre execution check
        if self.block < 0:
            self.log.debug("UNKNOWN JUMP ADDRESS. TERMINATING THIS PATH")
            return ["ERROR"]

        self.log.debug("Reach block address %d \n", self.block)
        self.log.debug("STACK: " + str(self.stack))

        current_edge = self.Edge(self.pre_block, self.block)
        if self.visited_edges.has_key(current_edge):
            updated_count_number = self.visited_edges[current_edge] + 1
            self.visited_edges.update({current_edge: updated_count_number})
        else:
            self.visited_edges.update({current_edge: 1})

        if self.visited_edges[current_edge] > global_params.LOOP_LIMIT:
            self.log.debug("Overcome a number of loop limit. Terminating this path ...")
            return self.stack

        current_gas_used = self.analysis["gas"]
        if current_gas_used > global_params.GAS_LIMIT:
            self.log.debug("Run out of gas. Terminating this path ... ")
            return self.stack

        # recursively execution instruction, one at a time
        try:
            block_ins = self.vertices[self.block].get_instructions()
        except KeyError:
            self.log.debug("This path results in an exception, possibly an invalid jump address")
            raise

        for instr in block_ins:
            self.sym_exec_ins(block, instr, stack, mem, memory, global_state, path_conditions_and_vars, analysis, path,
                         models)
            # Mark that this basic block in the visited blocks
        self.visited.append(self.block)
        self.depth += 1

        self.reentrancy_all_paths.append(self.analysis["reentrancy_bug"])
        if self.analysis["money_flow"] not in self.money_flow_all_paths:
            self.money_flow_all_paths.append(self.analysis["money_flow"])
            self.path_conditions.append(self.path_conditions_and_vars["path_condition"])
            self.all_gs.append(copy_global_values(self.global_state)) #TODO: import utils
        if global_params.DATA_FLOW:
            if self.analysis["sload"] not in self.data_flow_all_paths[0]:
                self.data_flow_all_paths[0].append(self.analysis["sload"])
            if self.analysis["sstore"] not in self.data_flow_all_paths[1]:
                self.data_flow_all_paths[1].append(self.analysis["sstore"])


        # Go to next Basic Block(s)
        if self.jump_type[self.block] == "terminal" or self.depth > global_params.DEPTH_LIMIT:
            self.log.debug("TERMINATING A PATH ...")
            display_analysis(analysis)
            global total_no_of_paths
            total_no_of_paths += 1
            if global_params.UNIT_TEST == 1:
                compare_stack_unit_test(stack)
            if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
                compare_storage_and_memory_unit_test(global_state, mem, analysis)

        elif self.jump_type[block] == "unconditional":  # executing "JUMP"
            successor = self.vertices[self.block].get_jump_target()
            stack1 = list(self.stack)
            mem1 = dict(self.mem)
            memory1 = list(self.memory)
            global_state1 = my_copy_dict(self.global_state)
            global_state1["pc"] = successor
            visited1 = list(self.visited)
            path_conditions_and_vars1 = my_copy_dict(self.path_conditions_and_vars)
            analysis1 = my_copy_dict(self.analysis)
            # TODO: what to do with this recursively executed func, with global state?
            sym_exec_block(successor, block, visited1, depth, stack1, mem1, memory1, global_state1,
                           path_conditions_and_vars1, analysis1, path + [block], models)
        elif self.jump_type[block] == "falls_to":  # just follow to the next basic block
            successor = vertices[block].get_falls_to()
            stack1 = list(stack)
            mem1 = dict(mem)
            memory1 = list(memory)
            global_state1 = my_copy_dict(global_state)
            global_state1["pc"] = successor
            visited1 = list(visited)
            path_conditions_and_vars1 = my_copy_dict(path_conditions_and_vars)
            analysis1 = my_copy_dict(analysis)
            sym_exec_block(successor, block, visited1, depth, stack1, mem1, memory1, global_state1,
                           path_conditions_and_vars1, analysis1, path + [block], models)
        elif jump_type[block] == "conditional":  # executing "JUMPI"

            # A choice point, we proceed with depth first search

            branch_expression = vertices[block].get_branch_expression()

            log.debug("Branch expression: " + str(branch_expression))

            solver.push()  # SET A BOUNDARY FOR SOLVER
            solver.add(branch_expression)

            try:
                if solver.check() == unsat:
                    log.debug("INFEASIBLE PATH DETECTED")
                else:
                    left_branch = vertices[block].get_jump_target()
                    stack1 = list(stack)
                    mem1 = dict(mem)
                    memory1 = list(memory)
                    global_state1 = my_copy_dict(global_state)
                    global_state1["pc"] = left_branch
                    visited1 = list(visited)
                    path_conditions_and_vars1 = my_copy_dict(path_conditions_and_vars)
                    path_conditions_and_vars1["path_condition"].append(branch_expression)
                    analysis1 = my_copy_dict(analysis)
                    sym_exec_block(left_branch, block, visited1, depth, stack1, mem1, memory1, global_state1,
                                   path_conditions_and_vars1, analysis1, path + [block], models + [solver.model()])
            except Exception as e:
                log_file.write(str(e))
                traceback.print_exc()
                if not global_params.IGNORE_EXCEPTIONS:
                    if str(e) == "timeout":
                        raise e

            solver.pop()  # POP SOLVER CONTEXT

            solver.push()  # SET A BOUNDARY FOR SOLVER
            negated_branch_expression = Not(branch_expression)
            solver.add(negated_branch_expression)

            log.debug("Negated branch expression: " + str(negated_branch_expression))

            try:
                if solver.check() == unsat:
                    # Note that this check can be optimized. I.e. if the previous check succeeds,
                    # no need to check for the negated condition, but we can immediately go into
                    # the else branch
                    log.debug("INFEASIBLE PATH DETECTED")
                else:
                    right_branch = vertices[block].get_falls_to()
                    stack1 = list(stack)
                    mem1 = dict(mem)
                    memory1 = list(memory)
                    global_state1 = my_copy_dict(global_state)
                    global_state1["pc"] = right_branch
                    visited1 = list(visited)
                    path_conditions_and_vars1 = my_copy_dict(path_conditions_and_vars)
                    path_conditions_and_vars1["path_condition"].append(negated_branch_expression)
                    analysis1 = my_copy_dict(analysis)
                    sym_exec_block(right_branch, block, visited1, depth, stack1, mem1, memory1, global_state1,
                                   path_conditions_and_vars1, analysis1, path + [block], models + [solver.model()])
            except Exception as e:
                log_file.write(str(e))
                traceback.print_exc()
                if not global_params.IGNORE_EXCEPTIONS:
                    if str(e) == "timeout":
                        raise e
            solver.pop()  # POP SOLVER CONTEXT
            updated_count_number = visited_edges[current_edge] - 1
            visited_edges.update({current_edge: updated_count_number})
        else:
            updated_count_number = visited_edges[current_edge] - 1
            visited_edges.update({current_edge: updated_count_number})
            raise Exception('Unknown Jump-Type')


    def sym_exec_ins(self):
        """"""
