#
# client library
#

import socket
import json
import struct
import re
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_PSS

# return hex encoding of a cryptographic hash of s.
def hash(s):
    if type(s) == str:
        # turn unicode into bytes.
        s = s.encode('utf-8')
    h = Crypto.Hash.SHA256.new()
    h.update(s)
    return h.hexdigest()

class Client:

    # name is user's human-readable name for her/himself, e.g. "sally".
    # hostport is server address, e.g. ( "127.0.0.1", 10223 )
    def __init__(self, name, hostport):
        self.name = name
        self.hostport = hostport
        self.masterkey = self.loadMasterKey()

    def put(self, k, v):
        # generate signature over json of k and v,
        # using master private key and RSASSA-PSS.
        kv = json.dumps([ self.name, k, v ])
        h = Crypto.Hash.SHA256.new()
        h.update(kv.encode('utf-8'))
        signer = Crypto.Signature.PKCS1_PSS.new(self.masterkey)
        signature = signer.sign(h)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "put", k, [ v, signature.hex() ] ])
        x = self.recv_json(s)
        s.close()

    # None, or a value.
    def get(self, k):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "get", k ])
        x = self.recv_json(s)
        s.close()
        # x is [ v, signature([name, k, v]) ]
        return x[0]

    # list of [ key, value ]
    def range(self, key1, key2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "range", key1, key2 ])
        x = self.recv_json(s)
        s.close()
        x1 = [ ]
        for xx in x:
            # xx is [ key, [ value, signature ] ]
            # eliminate signature
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

    # given the local user's name, either load public/private
    # key from a file, or create a key pair and store it.
    # returns a Crypto RSA key object.
    def loadMasterKey(self):
        hash('xx')
        name1 = re.sub(r'[^a-zA-Z0-9-]', 'x', self.name)
        keyfile = 'master-%s.pem' % (name1)
        f = None
        try:
            f = open(keyfile, 'rb')
        except:
            pass

        if f != None:
            kx = f.read()
            f.close()
            key = Crypto.PublicKey.RSA.importKey(kx)
            return key

        print("creating new master key for %s" % (self.name))
        key = Crypto.PublicKey.RSA.generate(2048)
        f = open(keyfile, "wb")
        f.write(key.exportKey('PEM'))
        f.close()

        return key

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
