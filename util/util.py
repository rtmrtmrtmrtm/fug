import Crypto.Hash.SHA256
import binascii
import sys

# return hex encoding of a cryptographic hash of s.
# returns a 64-byte str like '5dd389...'.
def hash(s):
    if type(s) == str:
        # turn unicode into bytes.
        s = s.encode('utf-8')
    h = Crypto.Hash.SHA256.new()
    h.update(s)
    return h.hexdigest()

# return a public key's finger print, as a hex str.
# key is a Crypto _RSAobj
def fingerprint(key):
    assert key.has_private() == False
    key = key.exportKey('PEM')
    key = hash(key)
    key = key.encode('utf-8') # turn unicode into bytes.
    key = key[0:32]
    key = key.hex()
    return key

def unhex(s):
    return binascii.unhexlify(s)


def yn():
    while True:
        sys.stdout.flush()
        x = sys.stdin.readline()
        if x == '':
            sys.exit(1)
        if x[0] in [ 'y', 'Y' ]:
            return True
        if x[0] in [ 'n', 'N' ]:
            return False
        sys.stdout.write("Please answer y or n: ")
