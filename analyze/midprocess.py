#encoding=utf-8
# ganben
# based on source, bytecode and opcode, replace op code and tokenize instr


import re
import tokenize
import zlib, base64
from tokenize import NUMBER, NAME, NEWLINE
import logging
from basicblock import BasicBlock


# default logger
log = logging.getLogger(__name__)

# find a callstack attack
def find_callstack(opcode):
    '''use simple rules: trace send, call, callcode, delegatecall's opcode
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

# format change and some value replace
def construction_sturct():
    '''prepare for further analyze TODO: a better func desgin
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

# this process tokens: must called in construction func
# 1. Parse the disassembled file
# 2. Then identify each basic block (i.e. one-in, one-out)
# 3. Store them in vertices
def cons_token2vertices(tokens):
    '''input token list, use a very long if elif block
    to 3 lists
    :return: {end_ins_dict}, {instructions}, {jump_type} = fun
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
    
    #IO data struct, to return
    end_ins_dict = {}
    instructions = {}
    jump_type = {}
    for tok_type, tok_string, (srow, scol), _, line_number in tokens:
        if wait_for_push is True:
            push_val = ""
            for ptok_type, ptok_string, _, _, _ in tokens:
                if ptok_type == NEWLINE:
                    is_new_line = True
                    current_line_content += push_val + ' '
                    instructions[current_ins_address] = current_line_content
                    log.debug(current_line_content)
                    current_line_content = ""
                    wait_for_push = False
                    break
                try:
                    int(ptok_string, 16)
                    push_val += ptok_string
                except ValueError:
                    pass

            continue
        elif is_new_line is True and tok_type == NUMBER:  # looking for a line number
            last_ins_address = current_ins_address
            try:
                current_ins_address = int(tok_string)
            except ValueError:
                log.critical("ERROR when parsing row %d col %d", srow, scol)
                quit()
            is_new_line = False
            if is_new_block:
                current_block = current_ins_address
                is_new_block = False
            continue
        elif tok_type == NEWLINE:
            is_new_line = True
            log.debug(current_line_content)
            instructions[current_ins_address] = current_line_content
            current_line_content = ""
            continue
        elif tok_type == NAME:
            if tok_string == "JUMPDEST":
                if last_ins_address not in end_ins_dict:
                    end_ins_dict[current_block] = last_ins_address
                current_block = current_ins_address
                is_new_block = False
            elif tok_string == "STOP" or tok_string == "RETURN" or tok_string == "SUICIDE" or tok_string == "REVERT" or tok_string == "ASSERTFAIL":
                jump_type[current_block] = "terminal"
                end_ins_dict[current_block] = current_ins_address
            elif tok_string == "JUMP":
                jump_type[current_block] = "unconditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string == "JUMPI":
                jump_type[current_block] = "conditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string.startswith('PUSH', 0):
                wait_for_push = True
            is_new_line = False
        if tok_string != "=" and tok_string != ">":
            current_line_content += tok_string + " "


    if current_block not in end_ins_dict:
        log.debug("current block: %d", current_block)
        log.debug("last line: %d", current_ins_address)
        end_ins_dict[current_block] = current_ins_address

    if current_block not in jump_type:
        jump_type[current_block] = "terminal"

    for key in end_ins_dict:
        if key not in jump_type:
            jump_type[key] = "falls_to"

    with open('vertercies', 'w') as of:
        of.write(str(end_ins_dict))
        of.write(str(instructions))
        of.write(jump_type)

    return end_ins_dict, instructions, jump_type

# construction on basic blocks
def cons_basicblock(end_ins_dict, instructions, jump_type):
    """read end_ins_dict and instance each key with basic blocks
    related func or tool: sorted, BasicBlock(k,e)
    :param: end_ins_dict, instructions, jump_type(f cons_token2vertices)
    :return: edges, vertices dicts
    """
    vertices = {}
    edges = {}
    sorted_addresses = sorted(instructions.keys())
    size = len(sorted_addresses)
    for key in end_ins_dict:
        end_address = end_ins_dict[key]
        block = BasicBlock(key, end_address)
        if key not in instructions:
            continue
        block.add_instruction(instructions[key])
        i = sorted_addresses.index(key) + 1
        while i < size and sorted_addresses[i] <= end_address:
            block.add_instruction(instructions[sorted_addresses[i]])
            i += 1
        block.set_block_type(jump_type[key])
        vertices[key] = block
        edges[key] = []

    return vertices, edges

# construct static edges
def cons_static_edges(jump_type, vertices, edges):
    """read jump_type and conditionally append to edges 
    :param: jump_type, vertices, edges
    :return: vertices, edges
    """
    key_list = sorted(jump_type.keys())
    length = len(key_list)
    for i, key in enumerate(key_list):
        if jump_type[key] != "terminal" and jump_type[key] != "unconditional" and i+1 < length:
            target = key_list[i+1]
            edges[key].append(target)
            vertices[key].set_falls_to(target)
    return vertices, edges

