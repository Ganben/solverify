#encoding=utf-8
# ganben
# detect 3 type bugs.transplant from oyente

import global_params
from varprepares import *
from z3 import *
from z3.z3util import get_vars
from generator import Generator


# detect money concurrency, if the flow is different then true
def detect_money_concurrency(money_flow_all_paths, all_gs, path_conditions):
    """detect mony concurrency return results
    :param: money_flow_all_path
    :returns: True/False"""
    i = 0
    false_positive = []
    concurrency_paths = []
    # results = {}
    n = len(money_flow_all_paths)
    for flow in money_flow_all_paths:
        i += 1
        if len(flow) == 1:
            continue  # pass all flows which do not do anything with money
        for j in range(i, n):
            jflow = money_flow_all_paths[j]
            if len(jflow) == 1:
                continue
            if is_diff(flow, jflow):
                concurrency_paths.append([i - 1, j])
                if global_params.CHECK_CONCURRENCY_FP and \
                        is_false_positive(i - 1, j, all_gs, path_conditions) and \
                        is_false_positive(j, i - 1, all_gs, path_conditions):
                    false_positive.append([i - 1, j])

    if len(concurrency_paths) > 0:
        # results['concurrency'] = True
        return True
    else:
        # results['concurrency'] = False
        return False
    # there are more information could be useful :TODO

# detect if there's data concurrency
# Detect if there is data concurrency in two different flows.
# e.g. if a flow modifies a value stored in the storage address and
# the other one reads that value in its execution
def detect_data_concurrency(data_flow_all_paths):
    """
    NOT SURE IF USED :TODO
    :param data_flow_all_paths:
    :return:
    """
    sload_flows = data_flow_all_paths[0]
    sstore_flows = data_flow_all_paths[1]
    concurrency_addr = []
    for sflow in sstore_flows:
        for addr in sflow:
            for lflow in sload_flows:
                if addr in lflow:
                    if not addr in concurrency_addr:
                        concurrency_addr.append(addr)
                    break
    # log.debug("data concurrency in storage " + str(concurrency_addr))
    return concurrency_addr

# Detect if any change in a storage address will result in a different
# flow of money. Currently I implement this detection by
# considering if a path condition contains
# a variable which is a storage address.
def detect_data_money_concurrency(money_flow_all_paths, data_flow_all_paths, path_conditions):
    """
    compare data / money flow at the same time
    :param money_flow_all_paths:
    :param data_flow_all_paths:
    :param path_conditions:
    :return concurrency_addr:
    """
    n = len(money_flow_all_paths)
    sstore_flows = data_flow_all_paths[1]
    concurrency_addr = []
    for i in range(n):
        cond = path_conditions[i]
        list_vars = []
        for expr in cond:
            list_vars += get_vars(expr)
        set_vars = set(i.decl().name() for i in list_vars)
        for sflow in sstore_flows:
            for addr in sflow:
                var_name = Generator.gen_owner_store_var(addr)
                if var_name in set_vars:
                    concurrency_addr.append(var_name)
    return concurrency_addr

# Detect if a money flow depends on the timestamp
def detect_time_dependency(path_conditions):
    """
    compare if TIMESTAMP var exist set vars
    :param path_conditions:
    :return:
    """
    TIMESTAMP_VAR = 'IH_s'
    index = 0
    for cond in path_conditions:
        index += 1
        list_vars = []
        for expr in cond:
            if is_expr(expr):
                list_vars += get_vars(expr)
        set_vars = set(i.decl().name() for i in list_vars)
        if TIMESTAMP_VAR in set_vars:
            return True

    return False

# new func, detect reentrancy bug found by one line
def detect_reentrancy(reentrancy_all_paths):
    """
    just check the symbolic exec data results
    :param reentrancy_all_paths:
    :return:
    """
    res = any([v for sublist in reentrancy_all_paths for v in sublist])

    return res
