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
from fuzz_test import *
from taskmonitor import WorkerThread
import uuid
import redis

app = Flask(__name__, static_url_path='/static/')
SESSION_TYPE = 'redis'
app.config.from_object(__name__)
CORS(app)
Session(app)

global statusList
statusList = []
status_source = redis.StrictRedis(host='localhost', port=6379, db=0)

# for fuzz test
FILE_PATH = '/tmp/sol/'

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
    task = new_task(task_id, statusList, status_source)

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

        try:
            res = parse_submit(task_id, incoming)
        
        except:
            return jsonify(task=task_id, res='parse fail')

        statusList.append(res)
        return jsonify(task=task_id, res='job append')


@app.route('/result', methods = ['GET'])
def result():
    # return generated results
    # TODO find the result by key = value
    # key = session.get('task', False)
    # print('%s' % session)
    res = generate_results(3, True)
    if not request.args.get('task', False):
        print('%s' % request.args)
        # TODO return error 401 or alike
        return abort(403)
    else:
        # TODO query the result session
        finded = query_task(request.args.get('task'), status_source)
        # print('%s' % finded)
        log.debug('querys=%s(%s)' % (finded, type(finded)))
        if not finded:
            time.sleep(1)
            finded = query_task(request.args.get('task'), status_source)            
            if not finded:
                time.sleep(1)
                finded = query_task(request.args.get('task'), status_source)

                return abort(404)
            else:
                return jsonify(finded)

        else:
            return jsonify(finded)


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
    thr = WorkerThread(1, statusList)
    try:
        thr.start()
    except KeyboardInterrupt:
        thr.keep_interrupt = True
        raise
    app.run(host='0.0.0.0', port=5005)