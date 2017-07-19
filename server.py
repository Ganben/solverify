#encoding=utf-8
#ganben
#this file is going to start a flask server, that can translate some file into the shell and return output
#via the API endpoint, in order to frond end web page to display.

from flask import Flask
from flask import request
import subprocess

app = Flask(__name__)

@app.route('/')
def hello():
    #TODO: add a index with form to paste code/contract address
    return "Hello World!"

@app.route("/sol", methods=['POST'])
def upload_sol():
    #upload sol and return results
    if not request.method == 'POST':
        return 'Only post solidity file allowed'
    result = {'reentry':False, 'concurrecy':False, 'timestamp':False, 'callstack':False}

    return request.form['name']


@app.route('/address/<c_addr>')
def c_address(c_addr):
    #download the contract code to perform a verification;
    #fan write crawler
    pass


