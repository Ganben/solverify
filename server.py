#encoding=utf-8
#ganben
#this file is going to start a flask server, that can translate some file into the shell and return output
#via the API endpoint, in order to frond end web page to display.

from flask import Flask, redirect, url_for
from flask import request
from flask import jsonify
import shlex, re, os
import subprocess
from analyze.verifier import Verifier

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
    v = Verifier()
    v.load_sol(solfile)
#    v.compile()
    v.check_all()
    return jsonify(result=v.results)



@app.route('/byte', methods=['GET', 'POST'])
def analyze():
    #upload bytecode and do analyzes, generate op code from bytecode
    if not request.method == 'POST':
        return '''
        <form method="post">
            <p><textarea cols=40 rows=10 name=code style="background-color:BFCEDC"></textarea>
            <p><input type=submit value=Analyze>
        </form>
    '''
    evmcode = request.form['code']
    v = Verifier()
    v.load_byte(evmcode)
#    v.compile()
    v.check_all()
    return jsonify(result=v.results)


@app.route('/address/<c_addr>')
def c_address(c_addr):
    #download the contract code to perform a verification, and generate analyze report
    #fan write crawler

    #pass
    return c_addr


