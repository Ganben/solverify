#encoding=utf-8
# ganben

from flask import redirect
from flask import send_from_directory
from flask import Flask
from flask import session
from flask_session import Session
from flask_cors import CORS
from flask_cors import cross_origin
from flask import jsonify
from flask import request
from flask import abort
from testdata import *
from taskstatus import *
import uuid

app = Flask(__name__, static_url_path='/static/')
SESSION_TYPE = 'redis'
app.config.from_object(__name__)
CORS(app)
Session(app)


@app.route('/submit', methods = ['POST', 'GET'])
def submit():
    # accept submitted config n code file
    incoming = {}

    # if session.get('task', False):
    #     # TODO process submitted data for existed key
    #     if request.method == 'POST':
    #         # check
    #         try:
    #             incoming['code'] = request.form['code']
    #             incoming['type'] = request.form['type']
    #             incoming['reentrancy'] = request.form['reentrancy']
    #             incoming['mislocking'] = request.form['mislocking']
    #             incoming['multisig'] = request.form['multisig']
    #         except:
    #             return abort(401)
    #     res = parse_submit(session['task'], incoming)
    #     if new_task(session['task']):
    #         return jsonify(task=session['task'])
    #     task_id = uuid.uuid4()
    #     return jsonify(task=task_id)
    # else:
    task_id = uuid.uuid4()
    task = new_task(task_id)

    if not task:
        return 'Queue Full Error'
    else:
        session['task'] = task_id
        if request.method == 'POST':
            # check
            try:
                incoming['code'] = request.form['code']
                incoming['type'] = request.form['type']
                incoming['reentrancy'] = request.form['reentrancy']
                incoming['mislocking'] = request.form['mislocking']
                incoming['multisig'] = request.form['multisig']
            except:
                return abort(404)

        res = parse_submit(task_id, incoming)
            # TODO process submitted data (task is returned obj)
        return jsonify(task=task_id)

@app.route('/result', methods = ['GET'])
def result():
    # return generated results
    # TODO find the result by key = value
    key = session.get('task', False)

    print('%s' % session)
    res = generate_results(3, True)
    if not request.args.get('task', False):
        print('%s' % request.args)
        # TODO return error 401 or alike
        return abort(403)
    else:
        # TODO query the result session
        finded = query_task(request.args.get('task'))
        if not finded:
            return jsonify(res)
            # return abort(404)
        else:
            return finded


@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('./static', path)

@app.route('/')
def hello():
    #TODO: add a index with form to paste code/contract address
    # return jsonify(result='Hello world', error = True)
    # return app.send_static_file('index.html')
    return redirect('/static/index.html')

if __name__ == '__main__':
    # TODO: create another async thread to monitoring incomming job
    print('list = %s' % len(statusList))

    app.run(host='0.0.0.0', port=5005)