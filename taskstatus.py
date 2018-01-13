#encoding=utf-8
# ganben

class Task(object):
    def load_file(self, filepath):
        self.file = filepath


def new_task():
    o = Task()
    return o