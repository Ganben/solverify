#encoding=utf-8
# ganben
# in this script the state and transition of state is symbolic executed


import json
import os
from z3 import *

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

    g_state['sender_address'] = in_state.get('sender_address', BitVec("Is", 256))
    path_conditions_and_vars["Is"] = g_state['sender_address']

    g_state['receiver_address'] = in_state.get('receiver_address', BitVec("Ia", 256))
    path_conditions_and_vars["Ia"] = g_state['receiver_address']

    g_state['value'] = in_state.get('deposited_value', BitVec("Iv", 256))
    path_conditions_and_vars["Iv"] = g_state['value']

    g_state["miu_i"] = 0

    g_state["gas_price"] =

    g_state["origin"] = origin

    g_state["currentCoinbase"] = currentCoinbase

    g_state["currentTimestamp"] = currentTimestamp

    g_state["currentNumber"] = currentNumber

    g_state["currentDifficulty"] = currentDifficulty

    g_state["currentGasLimit"] = currentGasLimit

    g_state["callData"] = callData

    return path_conditions_and_vars, g_state

