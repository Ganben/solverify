#encoding=utf-8
# ganben
# this is the class file which defines verification needed vars and funcs and checking processes

from z3 import *
import logging
import varprepares as vp
import midprocess as mp
import preprocess as pp

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

        if global_params.USE_GLOBAL_BLOCKCHAIN:
            self.data_source = EthereumData()

    def load_sol(self):
        """load a solidity source code, pass in a solidity code
        :param: source code text, multi lines
        :returns: True/Error
        """
        if not self.is_loaded:


    def load_byte(self):
        """load a evm source code, pass in a bytecode string
        :param: bytecode evm, single line
        :returns: True/Error
        """
        if not self.is_loaded:


    def check_all(self):
        """this func call all check items"""



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
            pass

    def check_