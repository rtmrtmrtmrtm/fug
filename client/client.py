#
# client library
# includes a bunch of useful stuff beyond basic server interaction.
#
# common format of all data inserted into DB for put(key, value):
#   dbkey = key
#   dbvalue = [ value, sign(key + value), myfingerprint ]
#
# format of a fingerprint -> publickey record:
#   key = "finger-" + my public key fingerprint
#   value = [ nickname, public key ]
#

import socket
import json
import struct
import re
import sys
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_PSS

sys.path.append("../util")
import util

class Client:

    # nickname is user's human-readable name for her/himself, e.g. "sally".
    # hostport is server address, e.g. ( "127.0.0.1", 10223 )
    def __init__(self, nickname, hostport):
        self.nickname = nickname
        self.hostport = hostport

        # XXX it's crazy to leave the master private key laying around.
        # ideally a separate agent process that would sign a certificate
        # saying that this app's private key speaks for the master.
        # sets self.masterkey and self.masterrandom
        self._loadMasterKey()

    # XXX should take an argument indicating who (if anyone)
    # we want to be able to read the k/v -- i.e. how to
    # seal it.
    def put(self, k, v):
        # generate signature over json of k and v,
        # using master private key and RSASSA-PSS.
        kv = json.dumps([ k, v ])
        h = Crypto.Hash.SHA256.new()
        h.update(kv.encode('utf-8'))
        signer = Crypto.Signature.PKCS1_PSS.new(self.masterkey)
        signature = signer.sign(h)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "put", k, [ v, signature.hex(), self.finger() ] ])
        x = self.recv_json(s)
        s.close()

    # low-level get; does not check signature.
    # returns None, or [ value, signature, fingerprint ]
    def lowget(self, k):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "get", k ])
        x = self.recv_json(s)
        s.close()
        return x

    # None, or a value.
    # note the signature covers the key and value together.
    # checks that the value is signed by the public
    # key it claims to be signed by (not very useful by itself).
    # XXX should take an argument indicating who we expect
    # to have signed it.
    def get(self, k):
        v = self.lowget(k)
        if v == None:
            # no DB entry for k.
            return None

        if self.check(k, v):
            return v[0]

        # signature did not verify!
        return None

    # check the signature on a k/v fetched from DB.
    # v is as returned by lowget.
    def check(self, k, v):
        pkv = self.lowget("finger-" + v[2])
        if pkv == None:
            # no entry for the fingerprint,
            # so pretend the DB entry is entirely missing.
            return False
        
        # v is [ value, signature, fingerprint ]
        # pkv [ [ nickname, public key ], signature, fingerprint ]

        # check the signature
        public = util.unbox(pkv[0][1])
        kv = json.dumps([ k, v[0] ])
        h = Crypto.Hash.SHA256.new()
        h.update(kv.encode('utf-8'))
        verifier = Crypto.Signature.PKCS1_PSS.new(public)
        ok = verifier.verify(h, util.unhex(v[1]))
        if ok == False:
            return False

        return True

    # list of [ key, value ]
    def range(self, key1, key2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "range", key1, key2 ])
        x = self.recv_json(s)
        s.close()
        x1 = [ ]
        for xx in x:
            # xx is [ key, [ value, signature, fingerprint ] ]
            if self.check(xx[0], xx[1]):
                x1.append( [ xx[0], xx[1][0] ] )
        return x1

    def send_json(self, s, obj):
        txt = bytes(json.dumps(obj), 'utf-8')
        s.sendall(struct.pack("I", len(txt)) + txt)
            
    def recv_json(self, s):
        lenbuf = self.recvn(s, 4)
        if lenbuf == None:
            return None
        n = struct.unpack("I", lenbuf)[0]
        jsonbuf = self.recvn(s, n)
        return json.loads(jsonbuf.decode('utf-8'))

    # read exactly n bytes from a socket.
    # returns None for EOF.
    def recvn(self, s, n):
        buf = b''
        while len(buf) < n:
            x = s.recv(n - len(buf))
            if len(x) == 0 and len(buf) == 0:
                return None
            if len(x) == 0:
                print("EOF in recvn %d" % (n))
                raise Exception('unexpected EOF')
            buf += x
        return buf

    ###
    ### below are methods for authentication, signing, and sealing.
    ### perhaps they should be somewhere else.
    ###

    # given the local user's nickname, either load public/private
    # key from a file, or create a key pair and store it.
    # the latter creates a new user identity.
    # returns a Crypto RSA key object.
    def _loadMasterKey(self):
        dir = "/tmp"

        nickname1 = re.sub(r'[^a-zA-Z0-9-]', 'x', self.nickname)
        keyfile = dir + "/" + 'fug-master-%s.pem' % (nickname1)
        f = None
        try:
            f = open(keyfile, 'rb')
        except:
            pass

        if f != None:
            kx = f.read()
            f.close()
            key = Crypto.PublicKey.RSA.importKey(kx)
        else:
            print("creating new master key for %s" % (self.nickname))
            key = Crypto.PublicKey.RSA.generate(2048)
            f = open(keyfile, "wb")
            f.write(key.exportKey('PEM'))
            f.close()

        self.masterkey = key

        keyfile = dir + "/" + 'fug-random-%s.pem' % (nickname1)
        f = None
        try:
            f = open(keyfile, 'rb')
        except:
            pass

        if f != None:
            rrr = f.read()
            f.close()
        else:
            print("creating new master randomness for %s" % (self.nickname))
            rrr = Crypto.Random.new().read(32)
            f = open(keyfile, "wb")
            f.write(rrr)
            f.close()

        # type is bytes
        self.masterrandom = rrr

        self.put("finger-" + self.finger(), [ self.nickname, util.box(self.publickey()) ] )

    # return the master public key.
    def publickey(self):
        return self.masterkey.publickey()

    # fingerprint of my master public key.
    # returns a hex str.
    def finger(self):
        return util.fingerprint(self.publickey())

    # look up a fingerprint in the DB, return nickname.
    # XXX should return a permanent local nickname, so that
    # the user can be assured that a given name always
    # refers to the same user.
    def finger2nickname(self, finger):
        x = self.get("finger-" + finger)
        if x == None:
            return None
        else:
            return x[0]

def tests():
    c = Client("client-test", ( "127.0.0.1", 10223 ))

    c.put("a", "aa")
    c.put("a1", "old")
    c.put("a1", "aa1")
    c.put("a2", "aa2")
    c.put("a3", "aa3")
    c.put("b", "bb")
    assert c.get("a1") == "aa1"

    z = c.range("a", "a2")
    # [ [ 'a1', 'aa1' ], [ 'a', 'aa' ] ]
    assert len(z) == 2
    assert [ 'a1', 'aa1' ] in z
    assert [ 'a', 'aa' ] in z

if __name__ == '__main__':
    tests()
