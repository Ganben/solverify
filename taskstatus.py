#encoding=utf-8
# ganben
import redis
import enum
from cachetools import LRUCache
import datetime

# global kv store and queue list
status_source = redis.StrictRedis(host='localhost', port=6379, db=0)
statusList = []

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

    def load_file(self, filepath):
        self.filepath = filepath


def new_task(ssid):
    # create a new task, save it's ssid, status, file
    # cache update
    if len(statusList) > 5:
        return False
    else:
        o = Task(ssid)
        sts = {}
        sts['status'] = State.accept
        status_source.set('latest', ssid)
        status_source.set(ssid, sts)
        print('list lenth %s: last: %s' % (len(statusList), str(ssid)))

    return o

def parse_submit(ssid, data_conf, data_code):
    # parse the submitted code and call external/internal module
    # TODO
    return 0
