import sys
import threading
import time

sys.path.append("../client")
import client

class Chat:
    # server is e.g. ( "127.0.0.1", 10223 )
    # myid is something unique.
    def __init__(self, server, myid):
        self.server = server
        self.myid = myid

    def poller(self):
        c = client.Client( self.server )
        while True:
            getrange...

    def go(self):
        th = threading.Thread(target=lambda : self.poller())
        th.daemon = True
        th.start()
        
        c = client.Client( self.server )
        while True:
            sys.stdout.write("%s> " % (self.myid))
            sys.stdout.flush()
            x = sys.stdin.readline()
            if x == '':
                break
            x = x[0:-1]

            msgid = "%d-%s" % (int(time.time()), self.myid)
            c.put(msgid, x)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        myid = sys.argv[1]
    else:
        sys.stderr.write("Usage: chat myid\n")
        sys.exit(1)
    ch = Chat(("127.0.0.1", 10223), myid)
    ch.go()
