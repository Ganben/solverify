#encoding=utf-8
# ganben for debug this class

from verifier import Verifier

try:
    v = Verifier()
    v.load_byte('60606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680633ccfd60b14610046578063b6b55f2514610058575bfe5b341561004e57fe5b610056610078565b005b341561006057fe5b6100766004808035906020019091905050610133565b005b3373ffffffffffffffffffffffffffffffffffffffff16600060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205460405180905060006040518083038185876187965a03f192505050506000600060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505b565b80600060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055505b505600')
except Exception:
    raise

try:
    v.check_all()
except Exception:
    raise


# print v.disasm
print v.reentrancy_all_paths