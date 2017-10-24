import socket
import threading
import time
import struct
import json

class Server:
    def __init__(self):
        self.db = { }

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", 10223))
        s.listen(100)
        th = threading.Thread(target=lambda : self.accept_loop(s))
        th.daemon = True
        th.start()

    # msg is [ "put", key, value ]
    def do_put(self, msg):
        self.db[msg[1]] = msg[2]
        return True

    # msg is [ "get", key ]
    def do_get(self, msg):
        ret = self.db.get(msg[1], None)
        return ret

    # msg is [ "range", key1, key2 ]
    # return value is list of [ key, value ]
    def do_range(self, msg):
        key1 = msg[1]
        key2 = msg[2]
        ret = [ [ k, self.db[k] ] for k in self.db.keys() if (k >= key1 and k < key2 ) ]
        return ret

    def accept_loop(self, s):
        while True:
            s1, addr = s.accept()
            th = threading.Thread(target=lambda : self.connection_loop(s1))
            th.daemon = True
            th.start()

    def connection_loop(self, s):
        while True:
            x = self.recv_json(s)
            if x == None:
                break
            if x[0] == "put":
                ret = self.do_put(x)
            elif x[0] == "get":
                ret = self.do_get(x)
            elif x[0] == "range":
                ret = self.do_range(x)
            else:
                sys.stderr.write("bad request %s\n" % (x))
                ret = False
            self.send_json(s, ret)
        s.close()
            
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

    def send_json(self, s, obj):
        txt = bytes(json.dumps(obj), 'utf-8')
        s.sendall(struct.pack("I", len(txt)) + txt)

if __name__ == '__main__':
    srv = Server()
    while True:
        time.sleep(1)
