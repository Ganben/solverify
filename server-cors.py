#encoding=utf-8
# ganben

from flask import Flask
from flask_cors import CORS
from flask_cors import cross_origin
from flask import jsonify
from flask import request
from analyze.verifier import Verifier
from testdata import *

app = Flask(__name__)
CORS(app)


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
    try:
        solfile = request.form['code']
        v = Verifier()
        v.load_sol(solfile)
#    v.compile()
        v.check_all()
    except Exception as e:
        return jsonify(error='Error %s' % e)

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
    try:
        evmcode = request.form['code']
        v = Verifier()
        v.load_byte(evmcode)
#    v.compile()
        v.check_all()
    except Exception as e:
        return jsonify(error='Error %s' % e)

    return jsonify(result=v.results)

@app.route('/submit', methods = ['POST'])
def submit():
    # accept submitted config n code file
    return jsonify(status='OK')

@app.route('/result', methods = ['GET'])
def result():
    # return generated results
    res = generate_results(10, True)
    return jsonify(res=res, error=None)

@app.route('/')
def hello():
    #TODO: add a index with form to paste code/contract address
    return jsonify(result='Hello world', error = True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)