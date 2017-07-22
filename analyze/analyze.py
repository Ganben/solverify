#encoding=utf-8
#ganben
#store 4 analyze process

import re
import tokenize



#find a callstack attack
def find_callstack(opcode):
    '''
    use simple rules: trace send, call, callcode, delegatecall's opcode
    then find if there follows: SWAP4, POP, POP, POP, POP, ISZERO
    :param opcode: the compiled opcode, is a serialized bytestring
    :return: result of the analysis
    '''
    instr_pattern = re.compile(b"([\d]+): ([A-Z]+)([\d]?)(?: 0x)?(\S+)?")
    instr = re.findall(instr_pattern, opcode)
    problematic_instructions = ['CALL', 'CALLCODE', 'SEND', 'DELEGATECALL']
    for i in xrange(0, len(instr)):
        instruction = instr[i]
        if instruction[1] in problematic_instructions:
            if not instr[i + 1][1] == 'SWAP':
                return True
            swap_num = int(instr[i + 1][2])
            for j in range(swap_num):
                if not instr[i + j + 2][1] == 'POP':
                    return True
            if not instr[i + swap_num + 2][1] == 'ISZERO':
                return True
    return False

#find a