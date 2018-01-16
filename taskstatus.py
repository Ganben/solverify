#encoding=utf-8
# ganben
import redis
import enum
from cachetools import LRUCache
import datetime
import os.path
from fuzz_test import *
import utils
import logging
import json

def init_logger():
    logger = logging.getLogger('status')
    ch = logging.FileHandler('statusHandle.log')
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.setLevel(logging.DEBUG)
    return logger

# global kv store and queue list
log = init_logger()

global RESULT
RESULT = {}

status_source = redis.StrictRedis(host='localhost', port=6379, db=0)
statusList = []
FILE_PATH = '/tmp/sol/' # use a temp dir
# TODO enum task state, category, label,
class State(enum.Enum):
    accept = 1
    processing = 2
    completed = 3

class Category(enum.Enum):
    transaction = 1
    time = 2
    recursive = 3
    etherflow = 4
    pattern = 5

class Label(enum.Enum):
    danger = 1
    warning = 2
    safe = 3
    info = 4

class Task(object):
    # log = init_logger()
    def __init__(self, ssid):
        self.ssid = str(ssid)
        self.status = State.accept

    # save code to file
    def save_file(self, code):
        self.filepath = os.path.join(FILE_PATH, str(self.ssid) + '.sol')
        with open(self.filepath, "w") as self.file:
            self.file.write(code)

        return self.filepath

    # change state of the task
    def pushto(self, file_num):
        if self.status == State.accept:
            self.status = State.processing
            # call or insert it to queue
            statusList.append(self)
            # call the process (should async TODO)
            try:
                res = fuzz_test(self.filepath, file_num, None, True)
                log.debug('%s' % len(res))
                log.debug('%s' % str(res[0]))
                log.debug('%s' % str(res[1]))
            # parse the result
                result = {'result': parse_result(res)}
                global RESULT 
                RESULT[self.ssid] = result
                log.debug('push to RESULT dict %s' % RESULT)
                status_source.set(self.ssid, json.dumps(result))
                log.debug('%s'% json.dumps(result))
                
            except:
                return False
            
            return True
        else:
            return False

    def finish(self):
        if self.status == State.processing:
            # get result from external format
            obj = status_source.get(self.ssid)
            if obj.get('result'):
                self.status = State.completed
                os.remove(self.filepath)
                os.remove('%s.ast.json' % self.filepath)
                statusList.remove(self)
                return obj.get('result')
            else:
                return False       
        
        else:
            return False


def new_task(ssid):
    # create a new task, save it's ssid, status, file
    # cache update
    if len(statusList) > 5:
        return False
    else:

        # sts = {}
        # sts['status'] = State.accept
        # statusList.append(ssid)
        status_source.set('latest', str(ssid))
        # status_source.set(ssid, sts)
        
        print('list lenth %s: last: %s' % (len(statusList), str(ssid)))

    return True

def query_task(task_id):
    log.debug('get task id: %s' % task_id)
    t = status_source.get(task_id)
    log.debug('fetch from cache %s' % t)
    if t:
        s = t.decode("utf-8")
        o = json.loads(s)
    
        if o:
        # try:
        #     obj = json.loads(t)
        # except:
        #     return False
            if o.get('result'):
                return o.get('result')
            else:
                return False
    else:
        b = status_source.get('latest')
        ssid = b.decode('utf-8')
        log.debug('get latest: %s' % ssid)
        t = status_source.get(ssid)
        log.debug('redis result: %s' % t)
        if t:
            try:
                o = json.loads(t)
                if o and o.get('result'):
                    return o.get('result')
            except:

                return RESULT[ssid]
            
        else:
            return RESULT[ssid]
        # if t:
        #     try:
        #         obj = json.loads(t)
        #     except:
        #         return False
        #     if obj.get('result'):
        #         return obj.get('result')
        #     else:
        #         return False
        # else:
        #     return False

def parse_submit(ssid, formdata):
    # parse the submitted code and call external/internal module
    # TODO
    # print('form = %s' % formdata)
    log.debug('incoming data %s' % formdata)
    t = Task(ssid)
    t.save_file(formdata['code'])
    return t.pushto(int(formdata['type']))


def parse_result(fuzzres):
    # parse the fuzz res to result
    text, lines = fuzzres
    textslist = str(text).split('\n')
    texts = '<br/>'.join(textslist)
    e = {
        'id': 0,
        'label': 1,
        'category': 3,
        'description': 'temporary not, should be filled',
        'name': 'to be filled',
        'input': 'base64xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'lines': lines
    }
    
    r = {
        'results': [e,],
        'charts': 'charts',
        'stat': texts,
        'error': 0
    }
    return r