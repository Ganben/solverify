#encoding=utf-8
#ganben
#this file is going to start a flask server, that can translate some file into the shell and return output
#via the API endpoint, in order to frond end web page to display.

from flask import Flask, redirect, url_for
from flask import request
import shlex, re, os
import subprocess

app = Flask(__name__)

@app.route('/')
def hello():
    #TODO: add a index with form to paste code/contract address
    return "Hello World!"

@app.route("/sol", methods=['GET', 'POST'])
def upload_sol():
    #upload sol and return results, use subprocess Popen constructor and PIP stdout
    if not request.method == 'POST':
        return '''
        <form method="post">
            <p><textarea cols=40 rows=10 name=code style="background-color:BFCEDC"></textarea>
            <p><input type=submit value=COMPILE>
        </form>
    '''
    solfile = request.form['code']
    with open('temp.sol', 'w') as tempfile:
        tempfile.write(solfile)
    solc_cmd = "solc --optimize --bin-runtime %s"
    #result = {'reentry':False, 'concurrecy':False, 'timestamp':False, 'callstack':False}
    res = subprocess.Popen(shlex.split(
      solc_cmd % 'temp.sol'
    ), stdout=subprocess.PIPE)
    resout = res.communicate()
    binary_regex = re.compile(b"\n======= (.*?) =======\nBinary of the runtime part: \n(.*?)\n")
    contracts = re.findall(binary_regex, resout[0])
    bit = []
    for (cname, bin_str) in contracts:
        bit.append(str(bin_str))
    os.remove('temp.sol')
    return ' '.join(bit)

@app.route('/byte', methods=['GET', 'POST'])
def upload_byte():
    #upload bytecode and do analyzes, generate op code from bytecode
    if not request.method == 'POST':
        return '''
        <form method="post">
            <p><textarea cols=40 rows=10 name=code style="background-color:BFCEDC"></textarea>
            <p><input type=submit value=EVM_OP>
        </form>
    '''
    bytefile = request.form['code']
    with open('temp.evm', 'w') as tempfile:
        tempfile.write(bytefile)
    try:
        disasm_p = subprocess.Popen(
            ["evm", "disasm", 'temp.evm'], stdout=subprocess.PIPE)
        disasm_out = disasm_p.communicate()[0]
    except:
        return "evm error"
    result = []
    result.append(str(disasm_out))
    os.remove('temp.evm')
    return '\n'.join(result)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    #upload bytecode and do analyzes, generate op code from bytecode
    if not request.method == 'POST':
        return '''
        <form method="post">
            <p><textarea cols=40 rows=10 name=code style="background-color:BFCEDC"></textarea>
            <p><input type=submit value=Analyze>
        </form>
    '''


@app.route('/address/<c_addr>')
def c_address(c_addr):
    #download the contract code to perform a verification, and generate analyze report
    #fan write crawler

    #pass
    return c_addr


