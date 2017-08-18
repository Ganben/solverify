#encoding=utf-8
# ganben
# this is the class file which defines verification needed vars and funcs and checking processes

from z3 import *
import logging
import zlib
import base64
import traceback
import varprepares as vp
import midprocess as mp
import preprocess as prp
import detect as dt
import global_params
from utils import *
from collections import namedtuple
from ethereum_data import *
from assertion import Assertion
from generator import Generator

UNSIGNED_BOUND_NUMBER = 2**256 - 1
CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)

class Verifier():
    """
    constructor: id;
    init process: init with sol, init with bytecode, init with opcode or other processed vars
    checker: every checker is a single function, must perform after success init
    output parameter: results
    returns for certain type check: result
    a centralized method to perform all checkers
    """
    # UNSIGNED_BOUND_NUMBER = 2 ** 256 - 1
    # CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)

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
        self.tokenlist = []
        self.block = 0
        self.pre_block = 0
        self.visited = []
        self.depth = 0
        self.stack = []
        self.mem = {}
        self.memory = []  # This memory is used only for the process of finding the position of a mapping
        #  variable in storage. In this process, memory is used for hashing methods

        g_state, in_state = vp.init_global_state()
        path_conditions_and_vars, g_state = vp.generate_defaults(g_state, in_state)

        self.global_state = g_state
        self.path_conditions_and_vars = path_conditions_and_vars
        # self.analysis = vp.init_analysis()
        self.path = []
        self.models = []

        self.gen = Generator()

        self.solver = Solver()
        self.solver.set("timeout", global_params.TIMEOUT)

        self.visited_edges = {}
        self.money_flow_all_paths = []
        self.data_flow_all_paths = [[], []]
        self.path_conditions = []
        self.all_gs =[]
        self.results = {}
        self.total_no_of_paths = 0
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
        self.assertions = []

        if global_params.USE_GLOBAL_BLOCKCHAIN:
            self.data_source = EthereumData()

    def compile(self):
        """this func exec compile and prepare script, read and fill self attrs
        :param: None
        :returns: True/False/Exceptions
        """
        if self.is_loaded:
            if not self.evm:
                _, _, eres = prp.sol_evm(self.sol)
                self.evm = eres[0]  #no need list, if so need depre sol input; :TODO: warn multi
            try:
                self.disasm_raw = evm_opcode(self.evm)
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
                # check callstack first:
                analysis = vp.init_analysis()
                self.check_callstack_attack()
                # find the initial exec of this analysis
                self.sym_exec_block(0, 0, self.visited, self.depth, self.stack,
                                    self.mem, self.memory, self.global_state, self.path_conditions_and_vars,
                                    analysis, [], [])
                # the given var and global var are still suspicious
            except Exception as e:
                self.log.error(' check all %s ' % e)
                raise

            # detect money concurrency:
            self.results['concurrency'] = dt.detect_money_concurrency(self.money_flow_all_paths,
                                                                      self.all_gs,
                                                                      self.path_conditions)

            # detect time dependency:
            self.results['time_dependency'] = dt.detect_time_dependency(self.path_conditions)

            # detect reentrancy bug:
            self.results['reentrancy'] = dt.detect_reentrancy(self.reentrancy_all_paths)
            #

        else:
            raise BaseException('Load source first')


    def check_callstack_attack(self):
        """check callstack bug
        :param: self.disasm
        :returns: results['callstack'] = True/False
        """
        if self.disasm:
            try:
                r = vp.run_callstack_attack(self.disasm_raw)
                self.results['callstack'] = r['callstack']
            except Exception as e:
                self.log.error(e)
                return None
            return self.results.get('callstack', True)
        else:
            raise ValueError('No disasm code found')

    def sym_exec_block(self, block, pre_block, visited, depth, stack, mem, memory, global_state, path_conditions_and_vars, analysis, path, models):
        """perform symbolic exec block by block
        :param block:
        :param pre_block:
        :param visited:
        :param depth:
        :param stack:
        :param mem:
        :param memory:
        :param global_state:
        :param path_conditions_and_vars:
        :param analysis:
        :param path:
        :param models:
        :return:
        """
        # block, pre_block, visited, depth, stack, mem, memory, global_state, path_conditions_and_vars, analysis, path, models
        # self. =
        # global solver
        # global visited_edges
        # global money_flow_all_paths
        # global data_flow_all_paths
        # global path_conditions
        # global all_gs
        # global results
        # pre execution check
        if block < 0:
            self.log.debug("UNKNOWN JUMP ADDRESS. TERMINATING THIS PATH")
            return stack

        self.log.debug("Reach block address %d \n", block)
        print 'stack = %s , mem = %s, gas = %s' % (stack, mem, analysis['gas'])
        self.log.debug("STACK: " + str(stack))

        current_edge = self.Edge(pre_block, block)
        if self.visited_edges.has_key(current_edge):
            updated_count_number = self.visited_edges[current_edge] + 1
            self.visited_edges.update({current_edge: updated_count_number})
        else:
            self.visited_edges.update({current_edge: 1})

        if self.visited_edges[current_edge] > global_params.LOOP_LIMIT:
            self.log.debug("Overcome a number of loop limit. Terminating this path ...")
            print ' branch 241 '
            return stack

        current_gas_used = analysis["gas"]
        if current_gas_used > global_params.GAS_LIMIT:
            self.log.debug("Run out of gas. Terminating this path ... ")
            print ' branch 247 '
            return stack

        # recursively execution instruction, one at a time
        try:
            block_ins = self.vertices[block].get_instructions()
        except KeyError:
            self.log.debug("This path results in an exception, possibly an invalid jump address")
            return stack

        for instr in block_ins:
            # must update many var from local scope due to shit old coding
            print 'exec instr %s ' % instr
            analysis, global_state, stack, memory, mem = self.sym_exec_ins(block, instr, stack, mem, memory, global_state, path_conditions_and_vars, analysis, path,
                         models)
            #
            # Mark that this basic block in the visited blocks
        visited.append(block)
        depth += 1

        self.reentrancy_all_paths.append(analysis["reentrancy_bug"])
        if analysis["money_flow"] not in self.money_flow_all_paths:
            self.money_flow_all_paths.append(analysis["money_flow"])
            self.path_conditions.append(self.path_conditions_and_vars["path_condition"])
            self.all_gs.append(copy_global_values(global_state)) #TODO: import utils
        if global_params.DATA_FLOW:
            if analysis["sload"] not in self.data_flow_all_paths[0]:
                self.data_flow_all_paths[0].append(analysis["sload"])
            if analysis["sstore"] not in self.data_flow_all_paths[1]:
                self.data_flow_all_paths[1].append(analysis["sstore"])


        # Go to next Basic Block(s)
        if self.jump_type[block] == "terminal" or depth > global_params.DEPTH_LIMIT:
            self.log.debug("TERMINATING A PATH ...")
            # display_analysis(analysis)
            self.log.debug('Money flow: %s ' % analysis.get('money_flow'))

            self.total_no_of_paths += 1
            if global_params.UNIT_TEST == 1:
                pass
                # useless exec
                # compare_stack_unit_test(stack)
            if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
                # later impl TODO
                pass
                # compare_storage_and_memory_unit_test(global_state, mem, analysis)

        elif self.jump_type[block] == "unconditional":  # executing "JUMP"
            print ' branch 295 '
            successor = self.vertices[block].get_jump_target()
            stack1 = list(stack)
            mem1 = dict(mem)
            memory1 = list(memory)
            global_state1 = my_copy_dict(global_state)
            global_state1["pc"] = successor
            visited1 = list(visited)
            path_conditions_and_vars1 = my_copy_dict(path_conditions_and_vars)
            analysis1 = my_copy_dict(analysis)
            res = self.sym_exec_block(successor, block, visited1, depth, stack1, mem1, memory1, global_state1,
                           path_conditions_and_vars1, analysis1, path + [block], models)
            if len(res) > len(stack):
                stack = res

        elif self.jump_type[block] == "falls_to":  # just follow to the next basic block
            print ' branch 305 '
            successor = self.vertices[block].get_falls_to()
            stack1 = list(stack)
            mem1 = dict(mem)
            memory1 = list(memory)
            global_state1 = my_copy_dict(global_state)
            global_state1["pc"] = successor
            visited1 = list(visited)
            path_conditions_and_vars1 = my_copy_dict(path_conditions_and_vars)
            analysis1 = my_copy_dict(analysis)
            res = self.sym_exec_block(successor, block, visited1, depth, stack1, mem1, memory1, global_state1,
                           path_conditions_and_vars1, analysis1, path + [block], models)
            if len(res) > len(stack):
                stack = res
        elif self.jump_type[block] == "conditional":  # executing "JUMPI"

            # A choice point, we proceed with depth first search

            branch_expression = self.vertices[block].get_branch_expression()

            self.log.debug("Branch expression: " + str(branch_expression))

            self.solver.push()  # SET A BOUNDARY FOR SOLVER
            self.solver.add(branch_expression)

            try:
                if self.solver.check() == unsat:
                    self.log.debug("INFEASIBLE PATH DETECTED")
                else:
                    print ' branch 335 %s' % depth
                    left_branch = self.vertices[block].get_jump_target()
                    stack1 = list(stack)
                    mem1 = dict(mem)
                    memory1 = list(memory)
                    global_state1 = my_copy_dict(global_state)
                    global_state1["pc"] = left_branch
                    visited1 = list(visited)
                    path_conditions_and_vars1 = my_copy_dict(path_conditions_and_vars)
                    path_conditions_and_vars1["path_condition"].append(branch_expression)
                    analysis1 = my_copy_dict(analysis)
                    res = self.sym_exec_block(left_branch, block, visited1, depth, stack1, mem1, memory1, global_state1,
                                   path_conditions_and_vars1, analysis1, path + [block], models + [self.solver.model()])
                    if len(res)>len(stack):
                        stack = res

            except Exception as e:
                self.log.error('recursive error: %s ' % e)
                # log_file.write(str(e))
                traceback.print_exc()
                if not global_params.IGNORE_EXCEPTIONS:
                    if str(e) == "timeout":
                        raise e

            self.solver.pop()  # POP SOLVER CONTEXT

            self.solver.push()  # SET A BOUNDARY FOR SOLVER
            negated_branch_expression = Not(branch_expression)
            self.solver.add(negated_branch_expression)

            self.log.debug("Negated branch expression: " + str(negated_branch_expression))

            try:
                if self.solver.check() == unsat:
                    # Note that this check can be optimized. I.e. if the previous check succeeds,
                    # no need to check for the negated condition, but we can immediately go into
                    # the else branch
                    self.log.debug("INFEASIBLE PATH DETECTED")
                else:
                    print ' total 371 depth %s' % depth
                    right_branch = self.vertices[block].get_falls_to()
                    stack1 = list(stack)
                    mem1 = dict(mem)
                    memory1 = list(memory)
                    global_state1 = my_copy_dict(global_state)
                    global_state1["pc"] = right_branch
                    visited1 = list(visited)
                    path_conditions_and_vars1 = my_copy_dict(path_conditions_and_vars)
                    path_conditions_and_vars1["path_condition"].append(negated_branch_expression)
                    analysis1 = my_copy_dict(analysis)
                    # print ' error sym block global %s ' % global_state
                    res = self.sym_exec_block(right_branch, block, visited1, depth, stack1, mem1, memory1, global_state1,
                                   path_conditions_and_vars1, analysis1, path + [block], models + [self.solver.model()])
                    if len(res)>len(stack):
                        stack = res
            except Exception as e:
                # log_file.write(str(e))
                traceback.print_exc()
                if not global_params.IGNORE_EXCEPTIONS:
                    if str(e) == "timeout":
                        raise e
            self.solver.pop()  # POP SOLVER CONTEXT
            updated_count_number = self.visited_edges[current_edge] - 1
            self.visited_edges.update({current_edge: updated_count_number})
        else:
            updated_count_number = self.visited_edges[current_edge] - 1
            self.visited_edges.update({current_edge: updated_count_number})
            raise Exception('Unknown Jump-Type')
        return stack


    def sym_exec_ins(self, start, instr, stack, mem, memory, global_state, path_conditions_and_vars, analysis, path, models):
        """
        :param start:
        :param instr:
        :param stack:
        :param mem:
        :param memory:
        :param global_state:
        :param path_conditions_and_vars:
        :param analysis:
        :param path:
        :param models:
        :return: analysis, global_state, stack, memory, mem
        """
        # global solver = self.
        # global vertices
        # global edges
        # global assertions   # ??? what is this used

        instr_parts = str.split(instr, ' ')

        if instr_parts[0] == "INVALID":
            return analysis, global_state, stack, memory, mem
        elif instr_parts[0] == "ASSERTFAIL":
            # We only consider assertions blocks that already start with ASSERTFAIL,
            # without any JUMPDEST
            if instr == self.vertices[start].get_instructions()[0]:
                from_block = path[-1]
                block_instrs = self.vertices[from_block].get_instructions()
                is_init_callvalue = True
                if len(block_instrs) < 5:
                    is_init_callvalue = False
                else:
                    instrs = ["JUMPDEST", "CALLVALUE", "ISZERO", "PUSH", "JUMPI"]
                    for i in range(0, 5):
                        if not block_instrs[i].startswith(instrs[i]):
                            is_init_callvalue = False
                            print '450 break'
                            break
                if from_block != 0 and not is_init_callvalue:
                    assertion = Assertion(start)
                    assertion.set_violated(True)
                    assertion.set_model(models[-1])
                    assertion.set_path(path + [start])
                    assertion.set_sym(path_conditions_and_vars)
                    self.assertions.append(assertion)
            return analysis, global_state, stack, memory, mem

        # collecting the analysis result by calling this skeletal function
        # this should be done before symbolically executing the instruction,
        # since SE will modify the stack and mem
        analysis = vp.update_analysis(analysis, instr_parts[0], stack, mem, global_state, path_conditions_and_vars, self.solver)
        # print ' ins updated %s ' % analysis
        # analysis.update(new_analysis)


        self.log.debug("==============================")
        self.log.debug("EXECUTING: " + instr)

        #
        #  0s: Stop and Arithmetic Operations
        #
        if instr_parts[0] == "STOP":
            global_state["pc"] = global_state["pc"] + 1
            return analysis, global_state, stack, memory, mem
        elif instr_parts[0] == "ADD":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                # Type conversion is needed when they are mismatched
                if vp.isReal(first) and vp.isSymbolic(second):
                    first = BitVecVal(first, 256)
                    computed = first + second
                elif vp.isSymbolic(first) and vp.isReal(second):
                    second = BitVecVal(second, 256)
                    computed = first + second
                else:
                    # both are real and we need to manually modulus with 2 ** 256
                    # if both are symbolic z3 takes care of modulus automatically
                    computed = (first + second) % (2 ** 256)
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "MUL":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.isReal(first) and vp.isSymbolic(second):
                    first = BitVecVal(first, 256)
                elif vp.isSymbolic(first) and vp.isReal(second):
                    second = BitVecVal(second, 256)
                computed = first * second & UNSIGNED_BOUND_NUMBER
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SUB":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.isReal(first) and vp.isSymbolic(second):
                    first = BitVecVal(first, 256)
                    computed = first - second
                elif vp.isSymbolic(first) and vp.isReal(second):
                    second = BitVecVal(second, 256)
                    computed = first - second
                else:
                    computed = (first - second) % (2 ** 256)
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "DIV":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    if second == 0:
                        computed = 0
                    else:
                        first = vp.to_unsigned(first)
                        second = vp.to_unsigned(second)
                        computed = first / second
                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(second == 0))
                    if self.solver.check() == unsat:
                        computed = 0
                    else:
                        computed = UDiv(first, second)
                    self.solver.pop()
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SDIV":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    first = vp.to_signed(first)
                    second = vp.to_signed(second)
                    if second == 0:
                        computed = 0
                    elif first == -2 ** 255 and second == -1:
                        computed = -2 ** 255
                    else:
                        sign = -1 if (first / second) < 0 else 1
                        computed = sign * (abs(first) / abs(second))
                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(second == 0))
                    if self.solver.check() == unsat:
                        computed = 0
                    else:
                        self.solver.push()
                        self.solver.add(Not(And(first == -2 ** 255, second == -1)))
                        if self.solver.check() == unsat:
                            computed = -2 ** 255
                        else:
                            self.solver.push()
                            self.solver.add(first / second < 0)
                            sign = -1 if self.solver.check() == sat else 1
                            z3_abs = lambda x: If(x >= 0, x, -x)
                            first = z3_abs(first)
                            second = z3_abs(second)
                            computed = sign * (first / second)
                            self.solver.pop()
                        self.solver.pop()
                    self.solver.pop()
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "MOD":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    if second == 0:
                        computed = 0
                    else:
                        first = vp.to_unsigned(first)
                        second = vp.to_unsigned(second)
                        computed = first % second & UNSIGNED_BOUND_NUMBER

                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)

                    self.solver.push()
                    self.solver.add(Not(second == 0))
                    if self.solver.check() == unsat:
                        # it is provable that second is indeed equal to zero
                        computed = 0
                    else:
                        computed = URem(first, second)
                    self.solver.pop()

                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SMOD":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    if second == 0:
                        computed = 0
                    else:
                        first = vp.to_signed(first)
                        second = vp.to_signed(second)
                        sign = -1 if first < 0 else 1
                        computed = sign * (abs(first) % abs(second))
                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)

                    self.solver.push()
                    self.solver.add(Not(second == 0))
                    if self.solver.check() == unsat:
                        # it is provable that second is indeed equal to zero
                        computed = 0
                    else:

                        self.solver.push()
                        self.solver.add(first < 0)  # check sign of first element
                        sign = BitVecVal(-1, 256) if self.solver.check() == sat \
                            else BitVecVal(1, 256)
                        self.solver.pop()

                        z3_abs = lambda x: If(x >= 0, x, -x)
                        first = z3_abs(first)
                        second = z3_abs(second)

                        computed = sign * (first % second)
                    self.solver.pop()

                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "ADDMOD":
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                third = stack.pop(0)

                if vp.contains_only_concrete_values([first, second, third]):
                    if third == 0:
                        computed = 0
                    else:
                        computed = (first + second) % third
                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(third == 0))
                    if self.solver.check() == unsat:
                        computed = 0
                    else:
                        first = ZeroExt(256, first)
                        second = ZeroExt(256, second)
                        third = ZeroExt(256, third)
                        computed = (first + second) % third
                        computed = Extract(255, 0, computed)
                    self.solver.pop()
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "MULMOD":
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                third = stack.pop(0)

                if vp.contains_only_concrete_values([first, second, third]):
                    if third == 0:
                        computed = 0
                    else:
                        computed = (first * second) % third
                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(third == 0))
                    if self.solver.check() == unsat:
                        computed = 0
                    else:
                        first = ZeroExt(256, first)
                        second = ZeroExt(256, second)
                        third = ZeroExt(256, third)
                        computed = URem(first * second, third)
                        computed = Extract(255, 0, computed)
                    self.solver.pop()
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "EXP":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                base = stack.pop(0)
                exponent = stack.pop(0)
                # Type conversion is needed when they are mismatched
                if vp.contains_only_concrete_values([base, exponent]):
                    computed = pow(base, exponent, 2 ** 256)
                else:
                    # The computed value is unknown, this is because power is
                    # not supported in bit-vector theory
                    new_var_name = self.gen.gen_arbitrary_var()
                    computed = BitVec(new_var_name, 256)
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SIGNEXTEND":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    if first >= 32 or first < 0:
                        computed = second
                    else:
                        signbit_index_from_right = 8 * first + 7
                        if second & (1 << signbit_index_from_right):
                            computed = second | (2 ** 256 - (1 << signbit_index_from_right))
                        else:
                            computed = second & ((1 << signbit_index_from_right) - 1)
                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(Or(first >= 32, first < 0)))
                    if self.solver.check() == unsat:
                        computed = second
                    else:
                        signbit_index_from_right = 8 * first + 7
                        self.solver.push()
                        self.solver.add(second & (1 << signbit_index_from_right) == 0)
                        if self.solver.check() == unsat:
                            computed = second | (2 ** 256 - (1 << signbit_index_from_right))
                        else:
                            computed = second & ((1 << signbit_index_from_right) - 1)
                        self.solver.pop()
                    self.solver.pop()
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        #
        #  10s: Comparison and Bitwise Logic Operations
        #
        elif instr_parts[0] == "LT":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    first = vp.to_unsigned(first)
                    second = vp.to_unsigned(second)
                    if first < second:
                        stack.insert(0, 1)
                    else:
                        stack.insert(0, 0)
                else:
                    sym_expression = If(ULT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
                    stack.insert(0, sym_expression)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "GT":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    first = vp.to_unsigned(first)
                    second = vp.to_unsigned(second)
                    if first > second:
                        stack.insert(0, 1)
                    else:
                        stack.insert(0, 0)
                else:
                    sym_expression = If(UGT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
                    stack.insert(0, sym_expression)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SLT":  # Not fully faithful to signed comparison
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    first = vp.to_signed(first)
                    second = vp.to_signed(second)
                    if first < second:
                        stack.insert(0, 1)
                    else:
                        stack.insert(0, 0)
                else:
                    sym_expression = If(first < second, BitVecVal(1, 256), BitVecVal(0, 256))
                    stack.insert(0, sym_expression)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SGT":  # Not fully faithful to signed comparison
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    first = vp.to_signed(first)
                    second = vp.to_signed(second)
                    if first > second:
                        stack.insert(0, 1)
                    else:
                        stack.insert(0, 0)
                else:
                    sym_expression = If(first > second, BitVecVal(1, 256), BitVecVal(0, 256))
                    stack.insert(0, sym_expression)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "EQ":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if vp.contains_only_concrete_values([first, second]):
                    if first == second:
                        stack.insert(0, 1)
                    else:
                        stack.insert(0, 0)
                else:
                    sym_expression = If(first == second, BitVecVal(1, 256), BitVecVal(0, 256))
                    stack.insert(0, sym_expression)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "ISZERO":
            # Tricky: this instruction works on both boolean and integer,
            # when we have a symbolic expression, type error might occur
            # Currently handled by try and catch
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                if vp.isReal(first):
                    if first == 0:
                        stack.insert(0, 1)
                    else:
                        stack.insert(0, 0)
                else:
                    sym_expression = If(first == 0, BitVecVal(1, 256), BitVecVal(0, 256))
                    stack.insert(0, sym_expression)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "AND":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                computed = first & second
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "OR":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)

                computed = first | second
                stack.insert(0, computed)

            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "XOR":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)

                computed = first ^ second
                stack.insert(0, computed)

            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "NOT":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                computed = (~first) & UNSIGNED_BOUND_NUMBER
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "BYTE":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                byte_index = 32 - first - 1
                second = stack.pop(0)

                if vp.contains_only_concrete_values([first, second]):
                    if first >= 32 or first < 0:
                        computed = 0
                    else:
                        computed = second & (255 << (8 * byte_index))
                        computed = computed >> (8 * byte_index)
                else:
                    first = vp.to_symbolic(first)
                    second = vp.to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(Or(first >= 32, first < 0)))
                    if self.solver.check() == unsat:
                        computed = 0
                    else:
                        computed = second & (255 << (8 * byte_index))
                        computed = computed >> (8 * byte_index)
                stack.insert(0, computed)
            else:
                raise ValueError('STACK underflow')
        #
        # 20s: SHA3
        #
        elif instr_parts[0] == "SHA3":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                s0 = stack.pop(0)
                s1 = stack.pop(0)
                if vp.contains_only_concrete_values([s0, s1]):
                    # simulate the hashing of sha3
                    data = [str(x) for x in memory[s0: s0 + s1]]
                    position = ''.join(data)
                    position = re.sub('[\s+]', '', position)
                    position = zlib.compress(position, 9)
                    position = base64.b64encode(position)
                    position = BitVec(position, 256)
                    stack.insert(0, position)
                else:
                    # push into the execution a fresh symbolic variable
                    new_var_name = self.gen.gen_arbitrary_var()
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                    stack.insert(0, new_var)
            else:
                raise ValueError('STACK underflow')
        #
        # 30s: Environment Information
        #
        elif instr_parts[0] == "ADDRESS":  # get address of currently executing account
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, path_conditions_and_vars["Ia"])
        elif instr_parts[0] == "BALANCE":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)
                if vp.isReal(address) and global_params.USE_GLOBAL_BLOCKCHAIN:
                    new_var = self.data_source.getBalance(address)
                else:
                    new_var_name = self.gen.gen_balance_var()
                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var
                if vp.isReal(address):
                    hashed_address = "concrete_address_" + str(address)
                else:
                    hashed_address = str(address)
                global_state["balance"][hashed_address] = new_var
                stack.insert(0, new_var)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "CALLER":  # get caller address
            # that is directly responsible for this execution
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["sender_address"])
        elif instr_parts[0] == "ORIGIN":  # get execution origination address
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["origin"])
        elif instr_parts[0] == "CALLVALUE":  # get value of this transaction
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["value"])
        elif instr_parts[0] == "CALLDATALOAD":  # from input data from environment
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                position = stack.pop(0)
                if global_params.INPUT_STATE and global_state["callData"]:
                    callData = global_state["callData"]
                    start = position * 2
                    end = start + 64
                    while end > len(callData):
                        # append with zeros if insufficient length
                        callData = callData + "0"
                    stack.insert(0, int(callData[start:end], 16))
                else:
                    new_var_name = self.gen.gen_data_var(position)
                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var
                    stack.insert(0, new_var)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "CALLDATASIZE":
            global_state["pc"] = global_state["pc"] + 1
            if global_params.INPUT_STATE and global_state["callData"]:
                stack.insert(0, len(global_state["callData"]) / 2)
            else:
                new_var_name = self.gen.gen_data_size()
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var)
        elif instr_parts[0] == "CALLDATACOPY":  # Copy input data to memory
            #  TODO: Don't know how to simulate this yet
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "CODESIZE":
            # if c_name.endswith('.disasm'):
            #     evm_file_name = c_name[:-7]
            # else:
            #     evm_file_name = c_name
            # with open(evm_file_name, 'r') as evm_file:
            #     evm = evm_file.read()[:-1]
            # rewrite for different data save loc
            evm = self.evm[:-1]
            code_size = len(evm) / 2
            stack.insert(0, code_size)
        elif instr_parts[0] == "CODECOPY":
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                mem_location = stack.pop(0)
                code_from = stack.pop(0)
                no_bytes = stack.pop(0)
                current_miu_i = global_state["miu_i"]

                if vp.contains_only_concrete_values([mem_location, current_miu_i, code_from, no_bytes]):
                    temp = long(math.ceil((mem_location + no_bytes) / float(32)))
                    if temp > current_miu_i:
                        current_miu_i = temp

                    # if c_name.endswith('.disasm'):
                    #     evm_file_name = c_name[:-7]
                    # else:
                    #     evm_file_name = c_name
                    # with open(evm_file_name, 'r') as evm_file:
                    #     evm = evm_file.read()[:-1]
                        evm = self.evm[:-1]
                        start = code_from * 2
                        end = start + no_bytes * 2
                        code = evm[start: end]
                    mem[mem_location] = code
                else:
                    new_var_name = self.gen.gen_code_var("Ia", code_from, no_bytes)
                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var

                    temp = ((mem_location + no_bytes) / 32) + 1
                    current_miu_i = vp.to_symbolic(current_miu_i)
                    expression = current_miu_i < temp
                    self.solver.push()
                    self.solver.add(expression)
                    if self.solver.check() != unsat:
                        current_miu_i = If(expression, temp, current_miu_i)
                    self.solver.pop()
                    mem.clear()  # very conservative
                    mem[str(mem_location)] = new_var
                global_state["miu_i"] = current_miu_i
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "GASPRICE":
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["gas_price"])
        elif instr_parts[0] == "EXTCODESIZE":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)
                if vp.isReal(address) and global_params.USE_GLOBAL_BLOCKCHAIN:
                    code = self.data_source.getCode(address)
                    stack.insert(0, len(code) / 2)
                else:
                    # not handled yet
                    stack.insert(0, 0)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "EXTCODECOPY":
            if len(stack) > 3:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)
                mem_location = stack.pop(0)
                code_from = stack.pop(0)
                no_bytes = stack.pop(0)
                current_miu_i = global_state["miu_i"]

                if vp.contains_only_concrete_values(
                        [address, mem_location, current_miu_i, code_from, no_bytes]) and global_params.USE_GLOBAL_BLOCKCHAIN:
                    temp = long(math.ceil((mem_location + no_bytes) / float(32)))
                    if temp > current_miu_i:
                        current_miu_i = temp

                    evm = self.data_source.getCode(address)
                    start = code_from * 2
                    end = start + no_bytes * 2
                    code = evm[start: end]
                    mem[mem_location] = code
                else:
                    new_var_name = self.gen.gen_code_var(address, code_from, no_bytes)
                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var

                    temp = ((mem_location + no_bytes) / 32) + 1
                    current_miu_i = vp.to_symbolic(current_miu_i)
                    expression = current_miu_i < temp
                    self.solver.push()
                    self.solver.add(expression)
                    if self.solver.check() != unsat:
                        current_miu_i = If(expression, temp, current_miu_i)
                    self.solver.pop()
                    mem.clear()  # very conservative
                    mem[str(mem_location)] = new_var
                global_state["miu_i"] = current_miu_i
            else:
                raise ValueError('STACK underflow')
        #
        #  40s: Block Information
        #
        elif instr_parts[0] == "BLOCKHASH":  # information from block header
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                new_var_name = "IH_blockhash"
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "COINBASE":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["currentCoinbase"])
        elif instr_parts[0] == "TIMESTAMP":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["currentTimestamp"])
        elif instr_parts[0] == "NUMBER":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["currentNumber"])
        elif instr_parts[0] == "DIFFICULTY":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["currentDifficulty"])
        elif instr_parts[0] == "GASLIMIT":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["currentGasLimit"])
        #
        #  50s: Stack, Memory, Storage, and Flow Information
        #
        elif instr_parts[0] == "POP":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "MLOAD":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)
                current_miu_i = global_state["miu_i"]
                if vp.contains_only_concrete_values([address, current_miu_i]) and address in mem:
                    temp = long(math.ceil((address + 32) / float(32)))
                    if temp > current_miu_i:
                        current_miu_i = temp
                    value = mem[address]
                    stack.insert(0, value)
                    self.log.debug("temp: " + str(temp))
                    self.log.debug("current_miu_i: " + str(current_miu_i))
                else:
                    temp = ((address + 31) / 32) + 1
                    current_miu_i = vp.to_symbolic(current_miu_i)
                    expression = current_miu_i < temp
                    self.solver.push()
                    self.solver.add(expression)
                    if self.solver.check() != unsat:
                        # this means that it is possibly that current_miu_i < temp
                        current_miu_i = If(expression, temp, current_miu_i)
                    self.solver.pop()
                    new_var_name = self.gen.gen_mem_var(address)
                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var
                    stack.insert(0, new_var)
                    if vp.isReal(address):
                        mem[address] = new_var
                    else:
                        mem[str(address)] = new_var
                    self.log.debug("temp: " + str(temp))
                    self.log.debug("current_miu_i: " + str(current_miu_i))
                global_state["miu_i"] = current_miu_i
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "MSTORE":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stored_address = stack.pop(0)
                stored_value = stack.pop(0)
                current_miu_i = global_state["miu_i"]
                if vp.isReal(stored_address):
                    # preparing data for hashing later
                    old_size = len(memory) // 32
                    new_size = ceil32(stored_address + 32) // 32
                    mem_extend = (new_size - old_size) * 32
                    memory.extend([0] * mem_extend)
                    for i in range(31, -1, -1):
                        memory[stored_address + i] = stored_value % 256
                        stored_value /= 256
                if vp.contains_only_concrete_values([stored_address, current_miu_i]):
                    temp = long(math.ceil((stored_address + 32) / float(32)))
                    if temp > current_miu_i:
                        current_miu_i = temp
                    mem[stored_address] = stored_value  # note that the stored_value could be symbolic
                    self.log.debug("temp: " + str(temp))
                    self.log.debug("current_miu_i: " + str(current_miu_i))
                else:
                    self.log.debug("temp: " + str(stored_address))
                    temp = ((stored_address + 31) / 32) + 1
                    self.log.debug("current_miu_i: " + str(current_miu_i))
                    expression = current_miu_i < temp
                    self.log.debug("Expression: " + str(expression))
                    self.solver.push()
                    self.solver.add(expression)
                    if self.solver.check() != unsat:
                        # this means that it is possibly that current_miu_i < temp
                        current_miu_i = If(expression, temp, current_miu_i)
                    self.solver.pop()
                    mem.clear()  # very conservative
                    mem[str(stored_address)] = stored_value
                    self.log.debug("temp: " + str(temp))
                    self.log.debug("current_miu_i: " + str(current_miu_i))
                global_state["miu_i"] = current_miu_i
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "MSTORE8":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stored_address = stack.pop(0)
                temp_value = stack.pop(0)
                stored_value = temp_value % 256  # get the least byte
                current_miu_i = global_state["miu_i"]
                if vp.contains_only_concrete_values([stored_address, current_miu_i]):
                    temp = long(math.ceil((stored_address + 1) / float(32)))
                    if temp > current_miu_i:
                        current_miu_i = temp
                    mem[stored_address] = stored_value  # note that the stored_value could be symbolic
                else:
                    temp = (stored_address / 32) + 1
                    if vp.isReal(current_miu_i):
                        current_miu_i = BitVecVal(current_miu_i, 256)
                    expression = current_miu_i < temp
                    self.solver.push()
                    self.solver.add(expression)
                    if self.solver.check() != unsat:
                        # this means that it is possibly that current_miu_i < temp
                        current_miu_i = If(expression, temp, current_miu_i)
                    self.solver.pop()
                    mem.clear()  # very conservative
                    mem[str(stored_address)] = stored_value
                global_state["miu_i"] = current_miu_i
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SLOAD":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)
                if address in global_state["Ia"]:
                    value = global_state["Ia"][address]
                    stack.insert(0, value)
                elif str(address) in global_state["Ia"]:
                    value = global_state["Ia"][str(address)]
                    stack.insert(0, value)
                else:
                    new_var_name = self.gen.gen_owner_store_var(address)
                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var
                    stack.insert(0, new_var)
                    if vp.isReal(address):
                        global_state["Ia"][address] = new_var
                    else:
                        global_state["Ia"][str(address)] = new_var
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SSTORE":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stored_address = stack.pop(0)
                stored_value = stack.pop(0)
                if vp.isReal(stored_address):
                    # note that the stored_value could be unknown
                    global_state["Ia"][stored_address] = stored_value
                else:
                    # note that the stored_value could be unknown
                    global_state["Ia"][str(stored_address)] = stored_value
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "JUMP":
            if len(stack) > 0:
                target_address = stack.pop(0)
                if vp.isSymbolic(target_address):
                    try:
                        target_address = int(str(simplify(target_address)))
                    except:
                        raise TypeError("Target address must be an integer")
                self.vertices[start].set_jump_target(target_address)
                if target_address not in self.edges[start]:
                    self.edges[start].append(target_address)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "JUMPI":
            # We need to prepare two branches
            if len(stack) > 1:
                target_address = stack.pop(0)
                if vp.isSymbolic(target_address):
                    try:
                        target_address = int(str(simplify(target_address)))
                    except:
                        raise TypeError("Target address must be an integer")
                self.vertices[start].set_jump_target(target_address)
                flag = stack.pop(0)
                branch_expression = (BitVecVal(0, 1) == BitVecVal(1, 1))
                if vp.isReal(flag):
                    if flag != 0:
                        branch_expression = True
                else:
                    branch_expression = (flag != 0)
                self.vertices[start].set_branch_expression(branch_expression)
                if target_address not in self.edges[start]:
                    self.edges[start].append(target_address)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "PC":
            stack.insert(0, global_state["pc"])
            global_state["pc"] = global_state["pc"] + 1
        elif instr_parts[0] == "MSIZE":
            global_state["pc"] = global_state["pc"] + 1
            msize = 32 * global_state["miu_i"]
            stack.insert(0, msize)
        elif instr_parts[0] == "GAS":
            # In general, we do not have this precisely. It depends on both
            # the initial gas and the amount has been depleted
            # we need o think about this in the future, in case precise gas
            # can be tracked
            global_state["pc"] = global_state["pc"] + 1
            new_var_name = self.gen.gen_gas_var()
            new_var = BitVec(new_var_name, 256)
            path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var)
        elif instr_parts[0] == "JUMPDEST":
            # Literally do nothing
            global_state["pc"] = global_state["pc"] + 1
        #
        #  60s & 70s: Push Operations
        #
        elif instr_parts[0].startswith('PUSH', 0):  # this is a push instruction
            position = int(instr_parts[0][4:], 10)
            global_state["pc"] = global_state["pc"] + 1 + position
            pushed_value = int(instr_parts[1], 16)
            stack.insert(0, pushed_value)
            if global_params.UNIT_TEST == 3:  # test evm symbolic
                stack[0] = BitVecVal(stack[0], 256)
        #
        #  80s: Duplication Operations
        #
        elif instr_parts[0].startswith("DUP", 0):
            global_state["pc"] = global_state["pc"] + 1
            position = int(instr_parts[0][3:], 10) - 1
            if len(stack) > position:
                duplicate = stack[position]
                stack.insert(0, duplicate)
            else:
                raise ValueError('STACK underflow')

        #
        #  90s: Swap Operations
        #
        elif instr_parts[0].startswith("SWAP", 0):
            global_state["pc"] = global_state["pc"] + 1
            position = int(instr_parts[0][4:], 10)
            if len(stack) > position:
                temp = stack[position]
                stack[position] = stack[0]
                stack[0] = temp
            else:
                raise ValueError('STACK underflow')

        #
        #  a0s: Logging Operations
        #
        elif instr_parts[0] in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
            global_state["pc"] = global_state["pc"] + 1
            # We do not simulate these log operations
            num_of_pops = 2 + int(instr_parts[0][3:])
            while num_of_pops > 0:
                stack.pop(0)
                num_of_pops -= 1

        #
        #  f0s: System Operations
        #
        elif instr_parts[0] == "CALL":
            # TODO: Need to handle miu_i
            if len(stack) > 6:
                global_state["pc"] = global_state["pc"] + 1
                outgas = stack.pop(0)
                recipient = stack.pop(0)
                transfer_amount = stack.pop(0)
                start_data_input = stack.pop(0)
                size_data_input = stack.pop(0)
                start_data_output = stack.pop(0)
                size_data_ouput = stack.pop(0)
                # in the paper, it is shaky when the size of data output is
                # min of stack[6] and the | o |

                if vp.isReal(transfer_amount):
                    if transfer_amount == 0:
                        stack.insert(0, 1)  # x = 0
                        return analysis, global_state, stack, memory, mem

                # Let us ignore the call depth
                balance_ia = global_state["balance"]["Ia"]
                is_enough_fund = (balance_ia < transfer_amount)
                self.solver.push()
                self.solver.add(is_enough_fund)

                if self.solver.check() == unsat:
                    # this means not enough fund, thus the execution will result in exception
                    self.solver.pop()
                    stack.insert(0, 0)  # x = 0
                else:
                    # the execution is possibly okay
                    stack.insert(0, 1)  # x = 1
                    self.solver.pop()
                    self.solver.add(is_enough_fund)
                    path_conditions_and_vars["path_condition"].append(is_enough_fund)
                    new_balance_ia = (balance_ia - transfer_amount)
                    global_state["balance"]["Ia"] = new_balance_ia
                    address_is = path_conditions_and_vars["Is"]
                    address_is = (address_is & CONSTANT_ONES_159)
                    boolean_expression = (recipient != address_is)
                    self.solver.push()
                    self.solver.add(boolean_expression)
                    if self.solver.check() == unsat:
                        self.solver.pop()
                        new_balance_is = (global_state["balance"]["Is"] + transfer_amount)
                        global_state["balance"]["Is"] = new_balance_is
                    else:
                        self.solver.pop()
                        if vp.isReal(recipient):
                            new_address_name = "concrete_address_" + str(recipient)
                        else:
                            new_address_name = self.gen.gen_arbitrary_address_var()
                        old_balance_name = self.gen.gen_arbitrary_var()
                        old_balance = BitVec(old_balance_name, 256)
                        path_conditions_and_vars[old_balance_name] = old_balance
                        constraint = (old_balance >= 0)
                        self.solver.add(constraint)
                        path_conditions_and_vars["path_condition"].append(constraint)
                        new_balance = (old_balance + transfer_amount)
                        global_state["balance"][new_address_name] = new_balance
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "CALLCODE":
            # TODO: Need to handle miu_i
            if len(stack) > 6:
                global_state["pc"] = global_state["pc"] + 1
                outgas = stack.pop(0)
                stack.pop(0)  # this is not used as recipient
                transfer_amount = stack.pop(0)
                start_data_input = stack.pop(0)
                size_data_input = stack.pop(0)
                start_data_output = stack.pop(0)
                size_data_ouput = stack.pop(0)
                # in the paper, it is shaky when the size of data output is
                # min of stack[6] and the | o |

                if vp.isReal(transfer_amount):
                    if transfer_amount == 0:
                        stack.insert(0, 1)  # x = 0
                        return analysis, global_state, stack, memory, mem

                # Let us ignore the call depth
                balance_ia = global_state["balance"]["Ia"]
                is_enough_fund = (balance_ia < transfer_amount)
                self.solver.push()
                self.solver.add(is_enough_fund)

                if self.solver.check() == unsat:
                    # this means not enough fund, thus the execution will result in exception
                    self.solver.pop()
                    stack.insert(0, 0)  # x = 0
                else:
                    # the execution is possibly okay
                    stack.insert(0, 1)  # x = 1
                    self.solver.pop()
                    self.solver.add(is_enough_fund)
                    path_conditions_and_vars["path_condition"].append(is_enough_fund)
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "RETURN" or instr_parts[0] == "REVERT":
            # TODO: Need to handle miu_i
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                stack.pop(0)
                # TODO
                pass
            else:
                raise ValueError('STACK underflow')
        elif instr_parts[0] == "SUICIDE":
            global_state["pc"] = global_state["pc"] + 1
            recipient = stack.pop(0)
            transfer_amount = global_state["balance"]["Ia"]
            global_state["balance"]["Ia"] = 0
            if vp.isReal(recipient):
                new_address_name = "concrete_address_" + str(recipient)
            else:
                new_address_name = self.gen.gen_arbitrary_address_var()
            old_balance_name = self.gen.gen_arbitrary_var()
            old_balance = BitVec(old_balance_name, 256)
            path_conditions_and_vars[old_balance_name] = old_balance
            constraint = (old_balance >= 0)
            self.solver.add(constraint)
            path_conditions_and_vars["path_condition"].append(constraint)
            new_balance = (old_balance + transfer_amount)
            global_state["balance"][new_address_name] = new_balance
            # TODO
            return analysis, global_state, stack, memory, mem

        else:
            self.log.debug("UNKNOWN INSTRUCTION: " + instr_parts[0])
            if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
                self.log.critical("Unkown instruction: %s" % instr_parts[0])
                # exit(UNKOWN_INSTRUCTION)
                pass
            raise Exception('UNKNOWN INSTRUCTION: ' + instr_parts[0])

        vp.print_state(stack, mem, global_state)
        # print 'yes returned, gas = %s ' % analysis['gas']
        return analysis, global_state, stack, memory, mem   #  , stack, memory, mem)

def evm_opcode(evmcode):
    """
    use subprocess call evm command to generate opcode
    :param evmcode: a stream of evm bytecode
    :return: a opcode, also in 'temp.disasm'
    """
    with open('temp.evm', 'w') as tempfile:
        tempfile.write(evmcode)
    try:
        disasm_p = subprocess.Popen(
            ["evm", "disasm", 'temp.evm'], stdout=subprocess.PIPE)
        disasm_out = disasm_p.communicate()[0]
    except Exception as e:
        # print(e)
        raise
    with open('temp.disasm', 'w') as tempfile:
        tempfile.write(disasm_out)
    return disasm_out

