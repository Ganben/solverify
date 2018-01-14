#encoding=utf-8
# ganben

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

app = Flask(__name__)
SESSION_TYPE = 'redis'
app.config.from_object(__name__)
CORS(app)
Session(app)


@app.route('/submit', methods = ['POST', 'GET'])
def submit():
    # accept submitted config n code file
    if session.get('task', False):
        # TODO process submitted data for existed key
        return 'OK: %s' % session['task']
    else:
        task_id = uuid.uuid4()
        task = new_task(task_id)

        if not task:
            return 'Queue Full Error'
        else:
            session['task'] = task_id
            # TODO process submitted data (task is returned obj)
            return 'OK'

@app.route('/result', methods = ['GET'])
def result():
    # return generated results
    # TODO find the result by key = value
    key = session.get('task', False)
    print('%s' % session)
    res = generate_results(3, True)
    if not key:
        # TODO return error 401 or alike
        return abort(403)
    else:
        # TODO query the result session

        return jsonify(res)

@app.route('/')
def hello():
    #TODO: add a index with form to paste code/contract address
    return jsonify(result='Hello world', error = True)

if __name__ == '__main__':
    # TODO: create another async thread to monitoring incomming job
    print('list = %s' % len(statusList))

    app.run(host='0.0.0.0', port=5005)