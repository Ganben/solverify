#encoding=utf-8
# ganben
import redis
import enum
from cachetools import LRUCache
import datetime
import os.path

# global kv store and queue list
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
    def __init__(self, ssid):
        self.ssid = ssid
        self.status = State.accept

    # save code to file
    def save_file(self, code):
        self.filepath = os.path.join(FILE_PATH, self.ssid + '.sol')
        with open(self.filepath, "w") as self.file:
            self.file.write(code)

        return self.filepath

    # change state of the task
    def pushto(self):
        if self.status == State.accept:
            self.status = State.processing
            # call or insert it to queue
            statusList.append(self)
            return True
        else:
            return False


def new_task(ssid, code):
    # create a new task, save it's ssid, status, file
    # cache update
    if len(statusList) > 5:
        return False
    else:

        sts = {}
        sts['status'] = State.accept
        status_source.set('latest', ssid)
        status_source.set(ssid, sts)
        t = Task(ssid)
        t.save_file(code)
        t.pushto()
        print('list lenth %s: last: %s' % (len(statusList), str(ssid)))

    return t

def query_task(task_id):
    if status_source.get(task_id, False):
        return status_source.get(task_id)
    else:
        return False

def parse_submit(ssid, formdata):
    # parse the submitted code and call external/internal module
    # TODO
    print('form = %s' % formdata)
    return 0
