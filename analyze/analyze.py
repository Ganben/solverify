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

#format change and some value replace
def construction_sturct():
    '''
    prepare for further analyze
    :param: read pre processed file, then change format
    :return: generate the required files [] for analyze
    '''
    SOLFILE = 'temp.sol'
    EVMFILE = 'temp.evm'
    DISASMFILE = 'temp.disasm'
    RPLACED = 'temp-replaced.disasm'
    TOKENFILE = 'temp-tokenlist.disasm'
    with open(DISASMFILE) as disasm_file:
        file_contents = disasm_file.readlines()
        i = 0
        firstLine = file_contents[0].strip('\n')
        for line in file_contents:
            line = line.replace('SELFDESTRUCT', 'SUICIDE')
            line = line.replace('Missing opcode 0xfd', 'REVERT')
            line = line.replace('Missing opcode 0xfe', 'ASSERTFAIL')
            line = line.replace('Missing opcode', 'INVALID')
            line = line.replace(':', '')
            lineParts = line.split(' ')
            try: # removing initial zeroes
                lineParts[0] = str(int(lineParts[0]))
            except:
                lineParts[0] = lineParts[0]
            lineParts[-1] = lineParts[-1].strip('\n')
            try: # adding arrow if last is a number
                lastInt = lineParts[-1]
                if(int(lastInt, 16) or int(lastInt, 16) == 0) and len(lineParts) > 2:
                    lineParts[-1] = "=>"
                    lineParts.append(lastInt)
            except Exception:
                pass

            file_contents[i] = ' '.join(lineParts)
            i = i + 1
        file_contents[0] = firstLine
        file_contents[-1] += '\n'
    with open(RPLACED, 'w') as disasm_file:
        disasm_file.write("\n".join(file_contents))

    with open(RPLACED, 'r') as disasm_file:
        disasm_file.readline()  # Remove first line
        tokens = tokenize.generate_tokens(disasm_file.readline)
        with open(TOKENFILE, 'w') as of:
            of.write(' '.join(str(tokens)))

    return [SOLFILE, EVMFILE, DISASMFILE, RPLACED, TOKENFILE]

#this process tokens
# 1. Parse the disassembled file
# 2. Then identify each basic block (i.e. one-in, one-out)
# 3. Store them in vertices
def token2vertices():
    '''
    read token list, use a very long if elif block
    to 3 lists
    :return: [end_ins_dict], [instructions], [jump_type]
    trying to implement better than origin
    '''

    #init conditions
    current_ins_address = 0
    last_ins_address = 0
    is_new_line = True
    current_block = 0
    current_line_content = ""
    wait_for_push = False
    is_new_block = False
    
