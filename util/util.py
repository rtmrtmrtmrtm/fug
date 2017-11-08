import Crypto.Hash.SHA256
import Crypto.Random
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

# turn a Crypto _RSAobj into a str hex
# suitable for insertion in the DB.
def box(pub):
    assert pub.has_private() == False
    return pub.exportKey('PEM').hex()

# turn a public key as retrieved from DB into a
# Crypto _RSAobj.
# argument must be str hex.
def unbox(txt):
    pub1 = unhex(txt)
    pub2 = Crypto.PublicKey.RSA.importKey(pub1)
    return pub2

def hex(b):
    return b.hex()

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


# a str with n bytes of random hex.
def randhex(n):
    rrr = Crypto.Random.new().read(n)
    return rrr.hex()[0:n]
