#encoding=utf-8
# ganben
# the threading is work for 

import threading
import time
import json
import logging
import redis
# from taskstatus import status_source
from taskstatus import parse_result
from taskstatus import generate_error_result
# from taskstatus import statusList
from taskstatus import Task
from fuzz_test import *  # external call module

# for fuzz test
FILE_PATH = '/tmp/sol/'

def init_logger():
    logger = logging.getLogger('worker')
    ch = logging.FileHandler('worker.log')
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.setLevel(logging.DEBUG)
    return logger

status_source = redis.StrictRedis(host='localhost', port=6379, db=0)

# global kv store and queue list
log = init_logger()

class WorkerThread (threading.Thread):
    def __init__(self,threadID, joblist):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.keep_interrupt = False
        self.joblist = joblist
        self.status_source = status_source

    def run(self):
        log.debug('--threading run--:%s' % self.threadID)
        while True and not self.keep_interrupt:
            if len(self.joblist)>0:
                jj = self.joblist.pop(0)
                log.debug('get a jj %s' % jj.ssid)
                try:
                    # time.sleep(3)
                    log.debug('init fuzz test:%s/%s' % (jj.filepath, jj.file_num))
                    log.debug('init fuzz test:%s/%s' %(type(jj.filepath), type(jj.file_num)))
                    res = fuzz_test(jj.filepath, jj.file_num, None, True)
                    log.debug('%s' % len(res))
                    log.debug('%s' % str(res[0]))
                    log.debug('%s' % str(res[1]))
                    # parse the result
                    result = {'result': parse_result(res, jj.cate)}
                    # global RESULT                
                    # log.debug('push to RESULT dict %s' % RESULT)
                    if self.status_source.set(jj.ssid, json.dumps(result)):
                        # RESULT[self.ssid] = result
                        log.debug('redis: %s'% json.dumps(result))
                    else:
                        log.error('redis dump error %s' % result)
                except Exception as e:
                    # generate error result
                    log.error('fuzz fail %s' % e)
                    self.status_source.set(jj.ssid, json.dumps(generate_error_result(jj.cate)))
                jj.finish()
            time.sleep(1)

    # def start(self):
    #     try:
    #         self._run()
    #     except KeyboardInterrupt:
    #         self.keep_interrupt = True
    #         raise
    #     return 0

