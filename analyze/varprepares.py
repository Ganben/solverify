#encoding=utf-8
# ganben
# in this script the state and transition of state is symbol variable prepared


import json
import re
import os
from z3 import *
from z3.z3util import get_vars
import logging
from opcode import *
# from global_params import *
import global_params

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
    return g_state, in_state


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

# default values of path_conditions_and_vars{}
def generate_defaults(g_state, in_state):
    """the empty keys in inputs are generated with defaults values
    the process returns path conditions and update g_state; using z3's BitVec func
    :param: g_state {} in_state {}
    :return: path_conditions_and_vars {}, g_state {}
    """
    path_conditions_and_vars = {"path_condition" : []}
    # BitVec is a z3 component
    # the path conditions and vars are very weird, more weird than their source code

    # a generator class is presumed to count and store a stack of the data
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

# calculate the gas( simulate ethereum)
def calculate_gas(opcode, stack, mem, global_state, analysis, solver):
    """this func has no global var definition so is cleanly trans
    it uses opcode file defined values to calculate gas
    :param: opcode, stack, mem, global_state, analysis dict and z3 solver obj
    :returns: gas_increment, new_gas_memory
    """
    gas_increment = get_ins_cost(opcode) # base cost
    gas_memory = analysis["gas_mem"]
    # In some opcodes, gas cost is not only depend on opcode itself but also current state of evm
    # For symbolic variables, we only add base cost part for simplicity
    if opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4") and len(stack) > 1:
        if isinstance(stack[1], (int, long)):
            gas_increment += GCOST["Glogdata"] * stack[1]
    elif opcode == "EXP" and len(stack) > 1:
        if isinstance(stack[1], (int, long)) and stack[1] > 0:
            gas_increment += GCOST["Gexpbyte"] * (1 + math.floor(math.log(stack[1], 256)))
    elif opcode == "EXTCODECOPY" and len(stack) > 2:
        if isinstance(stack[2], (int, long)):
            gas_increment += GCOST["Gcopy"] * math.ceil(stack[2] / 32)
    elif opcode in ("CALLDATACOPY", "CODECOPY") and len(stack) > 3:
        if isinstance(stack[3], (int, long)):
            gas_increment += GCOST["Gcopy"] * math.ceil(stack[3] / 32)
    elif opcode == "SSTORE" and len(stack) > 1:
        if isinstance(stack[1], (int, long)):
            try:
                storage_value = global_state['Ia'][str(stack[0])]
                # when we change storage value from zero to non-zero
                if storage_value == 0 and stack[1] != 0:
                    gas_increment += GCOST["Gsset"]
                else:
                    gas_increment += GCOST["Gsreset"]
            except: # when storage address at considered key is empty
                if stack[1] != 0:
                    gas_increment += GCOST["Gsset"]
                elif stack[1] == 0:
                    gas_increment += GCOST["Gsreset"]
        else:
            try:
                storage_value = global_state['Ia'][str(stack[0])]
                solver.push()
                solver.add(Not( And(storage_value == 0, stack[1] != 0) ))
                if solver.check() == unsat:
                    gas_increment += GCOST["Gsset"]
                else:
                    gas_increment += GCOST["Gsreset"]
                solver.pop()
            except:
                solver.push()
                solver.add(Not( stack[1] != 0 ))
                if solver.check() == unsat:
                    gas_increment += GCOST["Gsset"]
                else:
                    gas_increment += GCOST["Gsreset"]
                solver.pop()
    elif opcode == "SUICIDE" and len(stack) > 1:
        if isinstance(stack[1], (int, long)):
            address = stack[1] % 2**160
            if address not in global_state:
                gas_increment += GCOST["Gnewaccount"]
        else:
            address = str(stack[1])
            if address not in global_state:
                gas_increment += GCOST["Gnewaccount"]
    elif opcode in ("CALL", "CALLCODE", "DELEGATECALL") and len(stack) > 2:
        # Not fully correct yet
        gas_increment += GCOST["Gcall"]
        if isinstance(stack[2], (int, long)):
            if stack[2] != 0:
                gas_increment += GCOST["Gcallvalue"]
        else:
            solver.push()
            solver.add(Not (stack[2] != 0))
            if solver.check() == unsat:
                gas_increment += GCOST["Gcallvalue"]
            solver.pop()
    elif opcode == "SHA3" and isinstance(stack[1], (int, long)):
        pass # Not handle


    #Calculate gas memory, add it to total gas used
    length = len(mem.keys()) # number of memory words
    new_gas_memory = GCOST["Gmemory"] * length + (length ** 2) // 512
    gas_increment += new_gas_memory - gas_memory

    return (gas_increment, new_gas_memory)

# following are some useful funcs that from analysis.py

# Check if it is possible to execute a path after a previous path
# Previous path has prev_pc (previous path condition) and set global state variables as in gstate (only storage values)
# Current path has curr_pc
def is_feasible(prev_pc, gstate, curr_pc):
    vars_mapping = {}
    new_pc = list(curr_pc)
    for expr in new_pc:
        list_vars = get_vars(expr)
        for var in list_vars:
            vars_mapping[var.decl().name()] = var
    new_pc += prev_pc
    gen = Generator()
    for storage_address in gstate:
        var = gen.gen_owner_store_var(storage_address)
        if var in vars_mapping:
            new_pc.append(vars_mapping[var] == gstate[storage_address])
    solver = Solver()
    solver.set("timeout", global_params.TIMEOUT)
    solver.push()
    solver.add(new_pc)
    if solver.check() == unsat:
        solver.pop()
        return False
    else:
        solver.pop()
        return True


# detect if two flows are not really having race condition, i.e. check if executing path j
# after path i is possible.
# 1. We first start with a simple check to see if a path edit some storage variable
# which makes the other path infeasible
# 2. We then check if two paths cannot be executed next to each other, for example they
# are two paths yielded from this branch condition ``if (locked)"
# 3. More checks are to come
def is_false_positive(i, j, all_gs, path_conditions):
    pathi = path_conditions[i]
    pathj = path_conditions[j]
    statei = all_gs[i]

    # rename global variables in path i
    set_of_pcs, statei = rename_vars(pathi, statei)
    log.debug("Set of PCs after renaming global vars" + str(set_of_pcs))
    log.debug("Global state values in path " + str(i) + " after renaming: " + str(statei))
    if is_feasible(set_of_pcs, statei, pathj):
        return 0
    else:
        return 1


# Simple check if two flows of money are different
def is_diff(flow1, flow2):
    if len(flow1) != len(flow2):
        return 1
    n = len(flow1)
    for i in range(n):
        if flow1[i] == flow2[i]:
            continue
        try:
            tx_cd = Or(Not(flow1[i][0] == flow2[i][0]),
                       Not(flow1[i][1] == flow2[i][1]),
                       Not(flow1[i][2] == flow2[i][2]))
            solver = Solver()
            solver.set("timeout", global_params.TIMEOUT)
            solver.push()
            solver.add(tx_cd)

            if solver.check() == sat:
                solver.pop()
                return 1
            solver.pop()
        except Exception as e:
            return 1
    return 0

# update_analysis
def update_analysis(analysis, opcode, stack, mem, global_state, path_conditions_and_vars, solver):
    """unchanged trans

    :param analysis:
    :param opcode:
    :param stack:
    :param mem:
    :param global_state:
    :param path_conditions_and_vars:
    :param solver:
    :return: analysis,
    """
    gas_increment, gas_memory = calculate_gas(opcode, stack, mem, global_state, analysis, solver)
    analysis["gas"] += gas_increment
    analysis["gas_mem"] = gas_memory

    if opcode == "CALL":
        recipient = stack[1]
        transfer_amount = stack[2]
        reentrancy_result = check_reentrancy_bug(path_conditions_and_vars, global_state)
        analysis["reentrancy_bug"].append(reentrancy_result)
        if isinstance(transfer_amount, (int, long)) and transfer_amount == 0:
            return analysis
        if not isinstance(recipient, (int, long)):
            recipient = simplify(recipient)
        analysis["money_flow"].append(("Ia", str(recipient), transfer_amount))
    elif opcode == "SUICIDE":
        recipient = stack[0]
        if not isinstance(recipient, (int, long)):
            recipient = simplify(recipient)
        analysis["money_flow"].append(("Ia", str(recipient), "all_remaining"))
    # this is for data flow
    elif global_params.DATA_FLOW:
        if opcode == "SLOAD":
            if len(stack) > 0:
                address = stack[0]
                if not isinstance(address, (int, long)):
                    address = str(address)
                if address not in analysis["sload"]:
                    analysis["sload"].append(address)
            else:
                raise ValueError('STACK underflow')
        elif opcode == "SSTORE":
            if len(stack) > 1:
                stored_address = stack[0]
                stored_value = stack[1]
                log.debug(type(stored_address))
                # a temporary fix, not a good one.
                # TODO move to z3 4.4.2 in which BitVecRef is hashable
                if not isinstance(stored_address, (int, long)):
                    stored_address = str(stored_address)
                log.debug("storing value " + str(stored_value) + " to address " + str(stored_address))
                if stored_address in analysis["sstore"]:
                    # recording the new values of the item in storage
                    analysis["sstore"][stored_address].append(stored_value)
                else:
                    analysis["sstore"][stored_address] = [stored_value]
            else:
                raise ValueError('STACK underflow')
    return analysis

# for shit reason moved;
def print_state(stack, mem, global_state):
    log.debug("STACK: " + str(stack))
    log.debug("MEM: " + str(mem))
    log.debug("GLOBAL STATE: " + str(global_state))



def isSymbolic(value):
    return not isinstance(value, (int, long))

def isReal(value):
    return isinstance(value, (int, long))

# def isTesting():
#     return global_params.UNIT_TEST != 0

def contains_only_concrete_values(stack):
    for element in stack:
        if isSymbolic(element):
            return False
    return True

def to_symbolic(number):
    if isReal(number):
        return BitVecVal(number, 256)
    return number

def to_unsigned(number):
    if number < 0:
        return number + 2**256
    return number

def to_signed(number):
    if number > 2**(256 - 1):
        return (2**(256) - number) * (-1)
    else:
        return number


# utils partly
# Rename variables to distinguish variables in two different paths.
# e.g. Ia_store_0 in path i becomes Ia_store_0_old if Ia_store_0 is modified
# else we must keep Ia_store_0 if its not modified
def rename_vars(pcs, global_states):
    ret_pcs = []
    vars_mapping = {}

    for expr in pcs:
        list_vars = get_vars(expr)
        for var in list_vars:
            if var in vars_mapping:
                expr = substitute(expr, (var, vars_mapping[var]))
                continue
            var_name = var.decl().name()
            # check if a var is global
            if var_name.startswith("Ia_store_"):
                position = var_name.split('Ia_store_')[1]
                # if it is not modified then keep the previous name
                if position not in global_states:
                    continue
            # otherwise, change the name of the variable
            new_var_name = var_name + '_old'
            new_var = BitVec(new_var_name, 256)
            vars_mapping[var] = new_var
            expr = substitute(expr, (var, vars_mapping[var]))
        ret_pcs.append(expr)

    ret_gs = {}
    # replace variable in storage expression
    for storage_addr in global_states:
        expr = global_states[storage_addr]
        # z3 4.1 makes me add this line
        if is_expr(expr):
            list_vars = get_vars(expr)
            for var in list_vars:
                if var in vars_mapping:
                    expr = substitute(expr, (var, vars_mapping[var]))
                    continue
                var_name = var.decl().name()
                # check if a var is global
                if var_name.startswith("Ia_store_"):
                    position = int(var_name.split('_')[len(var_name.split('_'))-1])
                    # if it is not modified
                    if position not in global_states:
                        continue
                # otherwise, change the name of the variable
                new_var_name = var_name + '_old'
                new_var = BitVec(new_var_name, 256)
                vars_mapping[var] = new_var
                expr = substitute(expr, (var, vars_mapping[var]))
        ret_gs[storage_addr] = expr

    return ret_pcs, ret_gs


# Check if this call has the Reentrancy bug
# Return true if it does, false otherwise
def check_reentrancy_bug(path_conditions_and_vars, global_state):
    path_condition = path_conditions_and_vars["path_condition"]
    new_path_condition = []
    for expr in path_condition:
        if not is_expr(expr):
            continue
        list_vars = get_vars(expr)
        for var in list_vars:
            var_name = var.decl().name()
            # check if a var is global
            if var_name.startswith("Ia_store_"):
                storage_key = var_name.split("Ia_store_")[1]
                try:
                    if int(storage_key) in global_state["Ia"]:
                        new_path_condition.append(var == global_state["Ia"][int(storage_key)])
                except:
                    if storage_key in global_state["Ia"]:
                        new_path_condition.append(var == global_state["Ia"][storage_key])
    log.info("=>>>>>> New PC: " + str(new_path_condition))

    solver = Solver()
    solver.set("timeout", global_params.TIMEOUT)
    solver.push()
    solver.add(path_condition)
    solver.add(new_path_condition)
    # if it is not feasible to re-execute the call, its not a bug
    ret_val = not (solver.check() == unsat)
    solver.pop()
    log.info("Reentrancy_bug? " + str(ret_val))
    # global reported
    # if not reported:
    #     with open(reentrancy_report_file, 'a') as r_report:
    #         r_report.write('\n'+cur_file)
    #     reported = True
    print 'reentrancy value %s ' % ret_val
    return ret_val