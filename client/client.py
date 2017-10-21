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
        s.close()

    def send_json(self, s, obj):
        txt = bytes(json.dumps(obj), 'utf-8')
        s.sendall(struct.pack("I", len(txt)) + txt)

if __name__ == '__main__':
    c = Client(( "127.0.0.1", 10223 ))
    c.put("a", "b")
