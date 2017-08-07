#encoding=utf-8
# ganben
# in this script the state and transition of state is symbol variable prepared


import json
import re
import os
from z3 import *
import logging

# there are a variable generator class in neighbor file
from generator import Generator

# default logger
log = logging.getLogger(__name__)

def init_global_state(state=None):
    """this block read the state.json setting and generate state description
    :param:
    :return:
    """
    g_state = {"balance" : {}, "pc": 0}
    in_state = {}
    if state == None:
        g_state, in_state = read_state('state.json')

    # TODO: complete the rest of rewritted func



def read_state(filepath):
    """this func read state.json and parse to dicts
    :param: filepath
    :return: g_state {}, in_state {}
    """
    try:
        with open(filepath) as f:
            state = json.loads(f.read())
    except Exception as e:
        print("error %s" % e)
        return {}

    g_state = {"balance" : {}, "pc": 0}
    in_state = {}
    if state["Is"]["balance"]:
        in_state['init_is'] = int(state["Is"]["balance"], 16)
    if state["Ia"]["balance"]:
        in_state['init_ia'] = int(state["Ia"]["balance"], 16)
    if state["exec"]["value"]:
        in_state['deposited_value'] = int(state["exec"]["value"], 16)
    if state["Is"]["address"]:
        in_state['sender_address'] = int(state["Is"]["address"], 16)
    if state["Ia"]["address"]:
        in_state['receiver_address'] = int(state["Ia"]["address"], 16)
    if state["exec"]["gasPrice"]:
        in_state['gas_price'] = int(state["exec"]["gasPrice"], 16)
    if state["exec"]["origin"]:
        in_state['origin'] = int(state["exec"]["origin"], 16)
    if state["env"]["currentCoinbase"]:
        in_state['currentCoinbase'] = int(state["env"]["currentCoinbase"], 16)
    if state["env"]["currentNumber"]:
        in_state['currentNumber'] = int(state["env"]["currentNumber"], 16)
    if state["env"]["currentDifficulty"]:
        in_state['currentDifficulty'] = int(state["env"]["currentDifficulty"], 16)
    if state["env"]["currentGasLimit"]:
        in_state['currentGasLimit'] = int(state["env"]["currentGasLimit"], 16)
    if state["exec"]["data"]:
        callData = state["exec"]["data"]
        if callData[:2] == "0x":
            callData = callData[2:]
        in_state['callData'] = callData
    if state["Ia"]["storage"]:
        storage_dict = state["Ia"]["storage"]
        g_state["Ia"] = {}
        for key in storage_dict:
            g_state["Ia"][int(key, 16)] = int(storage_dict[key], 16)
        in_state['storage_dict'] = storage_dict

    return g_state, in_state

#default values of path_conditions_and_vars{}
def generate_defauls(g_state, in_state):
    """the empty keys in inputs are generated with defaults values
    the process returns path conditions and update g_state; using z3's BitVec func
    :param: g_state {} in_state {}
    :return: path_conditions_and_vars {}, g_state {}
    """
    path_conditions_and_vars = {"path_condition" : []}
    #BitVec is a z3 component
    #the path conditions and vars are very weird, more weird than their source code

    #a generator class is presumed to count and store a stack of the data
    gen = Generator()

    g_state['sender_address'] = in_state.get('sender_address', BitVec("Is", 256))
    path_conditions_and_vars["Is"] = g_state['sender_address']

    g_state['receiver_address'] = in_state.get('receiver_address', BitVec("Ia", 256))
    path_conditions_and_vars["Ia"] = g_state['receiver_address']

    g_state['value'] = in_state.get('deposited_value', BitVec("Iv", 256))
    path_conditions_and_vars["Iv"] = g_state['value']
    deposited_value = g_state['value']

    # calculate with init_Is and init_Ia

    init_is = in_state.get('init_Is', BitVec('init_Is', 256))
    init_ia = in_state.get('init_Ia', BitVec('init_Ia', 256))

    constraint = (deposited_value >= BitVecVal(0, 256))
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = (init_is >= deposited_value)
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = (init_ia >= BitVecVal(0, 256))
    path_conditions_and_vars["path_condition"].append(constraint)

    # update the balances of the "caller" and "callee"

    g_state["balance"]["Is"] = (init_is - deposited_value)
    g_state["balance"]["Ia"] = (init_ia + deposited_value)

    g_state["miu_i"] = 0

    g_state["gas_price"] = in_state.get('gas_price', BitVec(gen.gen_gas_price_var(), 256))
    path_conditions_and_vars[gen.gen_gas_price_var()] = g_state['gas_price']

    g_state["origin"] = in_state.get('origin', BitVec(gen.gen_origin_var(), 256))
    path_conditions_and_vars[gen.gen_origin_var()] = g_state['origin']

    g_state["currentCoinbase"] = in_state.get('currentCoinbase', BitVec('IH_c', 256))
    path_conditions_and_vars['IH_c'] = g_state['currentCoinbase']

    g_state["currentTimestamp"] = BitVec('IH_s', 256)
    path_conditions_and_vars['IH_s'] = g_state['currentTimestamp']

    g_state["currentNumber"] = in_state.get('currentNumber', BitVec('IH_i', 256))
    path_conditions_and_vars['IH_i'] = g_state['currentNumber']

    g_state["currentDifficulty"] = in_state.get('currentDifficulty', BitVec('IH_d', 256))
    path_conditions_and_vars['IH_d'] = g_state['currentDifficulty']

    g_state["currentGasLimit"] = in_state.get('currentGasLimit', BitVec('IH_l', 256))
    path_conditions_and_vars['IH_l'] = g_state['currentGasLimit']

    g_state["callData"] = in_state.get('callData')

    if 'Ia' not in g_state:
        g_state['Ia'] = {}

    return path_conditions_and_vars, g_state


# pure dict generate func
def init_analysis():
    """generate a dict
    :return: analysis {}
    """
    analysis = {
        "gas": 0,
        "gas_mem": 0,
        "money_flow": [("Is", "Ia", "Iv")],  # (source, destination, amount)
        "sload": [],
        "sstore": {},
        "reentrancy_bug":[]
    }
    return analysis


# in symbolic execute main process functions
def contains_only_concrete_values(stack):
    """use z3 to judge a instr
    :param: stack variable of instr simulation
    :return: True/False result
    """
    for element in stack:
        if isSymbolic(element):
            return False
    return True


# check for evm sequence SWAP4, POP, POP, POP, POP, ISZERO
def check_callstack_attack(disasm):
    """check callstack attack in disasm opcode (pattern matched)
    :param: replaced disasm bytecode
    :returns: result True/False
    """
    problematic_instructions = ['CALL', 'CALLCODE']
    for i in xrange(0, len(disasm)):
        instruction = disasm[i]
        if instruction[1] in problematic_instructions:
            if not disasm[i+1][1] == 'SWAP':
                return True
            swap_num = int(disasm[i+1][2])
            for j in range(swap_num):
                if not disasm[i+j+2][1] == 'POP':
                    return True
            if not disasm[i + swap_num + 2][1] == 'ISZERO':
                return True
    return False

# run a simulation of callstack attack
def run_callstack_attack(disasm):
    """ perform a regrex instruction pattern to perform callstack attack
    :param: disasm opcode
    :return: results dictionary
    """
    results = {}
    # disasm_data = open(c_name).read()
    instr_pattern = r"([\d]+): ([A-Z]+)([\d]?)(?: 0x)?(\S+)?"
    instr = re.findall(instr_pattern, disasm)
    result = check_callstack_attack(instr)

    log.info("\t  CallStack Attack: \t %s", result)
    results['callstack'] = result
    return results