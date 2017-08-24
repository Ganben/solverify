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
from datetime import timedelta
from flask import make_response, request, current_app
from functools import update_wrapper


def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator


app = Flask(__name__)

@app.route('/')
def hello():
    #TODO: add a index with form to paste code/contract address
    return "Hello World!"

@app.route("/sol", methods=['GET', 'POST'])
@crossdomain(origin='*')
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
@crossdomain(origin='*')
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


