#
# client library
#

import socket
import json
import struct

class Client:

    # hostport is server address, e.g. ( "127.0.0.1", 10223 )
    def __init__(self, hostport):
        self.hostport = hostport

    def put(self, k, v):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "put", k, v ])
        x = self.recv_json(s)
        s.close()

    # None, or a value.
    def get(self, k):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "get", k ])
        x = self.recv_json(s)
        s.close()
        return x

    # list of [ key, value ]
    def range(self, key1, key2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "range", key1, key2 ])
        x = self.recv_json(s)
        s.close()
        return x

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

if __name__ == '__main__':
    c = Client(( "127.0.0.1", 10223 ))
    c.put("a", "aa")
    c.put("a1", "aa1")
    c.put("a2", "aa2")
    c.put("a3", "aa3")
    c.put("b", "bb")
    assert c.get("a1") == "aa1"

    z = c.range("a", "a2")
    assert z == [ [ 'a1', 'aa1' ], [ 'a', 'aa' ] ]
