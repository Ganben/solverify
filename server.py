#encoding=utf-8
#ganben
#this file is going to start a flask server, that can translate some file into the shell and return output
#via the API endpoint, in order to frond end web page to display.

from flask import Flask, redirect, url_for
from flask import request
import shlex
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
            <p><input type=submit value=Verify>
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
    return resout


@app.route('/address/<c_addr>')
def c_address(c_addr):
    #download the contract code to perform a verification;
    #fan write crawler

    #pass
    return c_addr


