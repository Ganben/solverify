
import testdata

# SAMPLE_RESULT = generate_results(10, True)


def generate_results(num, error_flag):
    res = {}
    res['results'] = generate_item(num)
    res['charts'] = generate_charts()
    res['stat'] = generate_stat()
    res['error'] = generate_error(error_flag)
    print('res=%s' % res)
    return res

def generate_item(num):
    res = []
    for i in range(0, num):
        it = {}
        it['id'] = i
        it['label'] = 'error'
        it['category'] = 'trans'
        it['icon'] = '/icon/error1.png'
        it['description'] = 'error description 1'
        it['name'] = 'Huge error'
        it['lines'] = 15+i*2
        res.append(it)
    return res

def generate_charts():
    return 'charts'

def generate_stat():
    return 'stat'

def generate_error(flag):
    if not flag:
        return 1
    else:
        return 0



