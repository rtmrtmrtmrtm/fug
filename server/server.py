import socket
import threading
import time
import struct
import json

class Server:
    def __init__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", 10223))
        s.listen(100)
        th = threading.Thread(target=lambda : self.accept_loop(s))
        th.daemon = True
        th.start()

    def accept_loop(self, s):
        while True:
            s1, addr = s.accept()
            th = threading.Thread(target=lambda : self.connection_loop(s1))
            th.daemon = True
            th.start()

    def connection_loop(self, s):
        while True:
            x = self.recv_json(s)
            print("json recv: %s" % (x))
        s.close()
            
    def recv_json(self, s):
        lenbuf = self.recvn(s, 4)
        n = struct.unpack("I", lenbuf)[0]
        jsonbuf = self.recvn(s, n)
        return json.loads(jsonbuf.decode('utf-8'))

    # read exactly n bytes from a socket.
    def recvn(self, s, n):
        buf = b''
        while len(buf) < n:
            x = s.recv(n - len(buf))
            if len(x) == 0:
                print("EOF in recvn %d" % (n))
                raise Exception('unexpected EOF')
            buf += x
        return buf

if __name__ == '__main__':
    srv = Server()
    while True:
        time.sleep(1)
