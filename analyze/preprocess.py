#encoding=utf-8
#ganben
#the file saved 4 implementation of example project
#it refracted the IO and preprocess of sol, evm, and op code files

import subprocess
import os
import re
import shlex

#the sol to evm function
def sol2evm(solcode):
    '''
    use subprocess PIPE to call solc command, generate evm
    :param solcode: string of input solidity code
    :return: a list of cname, a list evm bytecode
    '''
    with open('temp.sol', 'w') as tempfile:
        tempfile.write(solcode)
    solc_cmd = "solc --optimize --bin-runtime %s"
    #result = {'reentry':False, 'concurrecy':False, 'timestamp':False, 'callstack':False}
    res = subprocess.Popen(shlex.split(
      solc_cmd % 'temp.sol'
    ), stdout=subprocess.PIPE)
    resout = res.communicate()
    binary_regex = re.compile(b"\n======= (.*?) =======\nBinary of the runtime part: \n(.*?)\n")
    contracts = re.findall(binary_regex, resout[0])
    filelist = []
    evmlist = []
    for (cname, bin_str) in contracts:
        filename = 'temp-%s.evm' % cname
        evmlist.append(bin_str)
        filelist.append(filename)
        with open(filename, 'w') as tfile:
            tfile.write(bin_str)
    return filelist, evmlist

#this is to read evm code and generate opcode and file
def evm2opcode(evmcode):
    '''
    use subprocess call evm command to generate opcode
    :param evmcode: a stream of evm bytecode
    :return: a opcode, also in 'temp.disasm'
    '''
    with open('temp.evm', 'w') as tempfile:
        tempfile.write(evmcode)
    try:
        disasm_p = subprocess.Popen(
            ["evm", "disasm", 'temp.evm'], stdout=subprocess.PIPE)
        disasm_out = disasm_p.communicate()[0]
    except:
        return "evm error"
    with open('temp.disasm', 'w') as tempfile:
        tempfile.write(disasm_out)
    return disasm_out

