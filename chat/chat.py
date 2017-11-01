#
# chat nickname --open roomname
# chat nickname --closed roomname
# chat nickname --list
# chat nickname --join
#
# open announcement:
#   key = ownerfingerprint-"room"-roomid
#   value = [ roomname, roomid ]
# open message:
#   key = roomid-timestamp-fromfingerprint
#   value = [ 'message', 'the message' ]
#
# closed announcement:
#   key = 
#   value = 
# closed participant list entry:
#   key = 
#   value = 
# closed message (one per recipient):
#   key = roomid-tofingerprint-timestamp
#   value = 
#

import sys
import threading
import time

sys.path.append("../client")
import client
sys.path.append("../util")
import util

class Chat:
    # server is e.g. ( "127.0.0.1", 10223 )
    # nickname is e.g. "fred".
    def __init__(self, server, nickname):
        self.server = server
        self.nickname = nickname

    def open_poller(self):
        c = client.Client(self.nickname, self.server)
        ts1 = 0
        while True:
            ts2 = int(time.time())
            rows = c.range(self.roomid + "-" + str(ts1), self.roomid + "-" + str(ts2))
            for row in rows:
                key = row[0]
                [ ty, txt ] = row[1]
                [ roomid, timestamp, finger ] = key.split("-")
                timestamp = int(timestamp)
                if timestamp > ts1 and ty == "message":
                    ts1 = timestamp
                    if finger != c.finger():
                        nn = c.finger2nickname(finger)
                        print("%s: %s" % (nn, txt))
            time.sleep(1)

    def go_open(self):
        th = threading.Thread(target=lambda : self.open_poller())
        th.daemon = True
        th.start()
        
        c = client.Client(self.nickname, self.server)
        while True:
            sys.stdout.write("%s> " % (self.nickname))
            sys.stdout.flush()
            txt = sys.stdin.readline()
            if txt == '':
                break
            txt = txt[0:-1]

            if len(txt) > 0:
                msgid = "%s-%d-%s" % (self.roomid, int(time.time()), c.finger())
                c.put(msgid, [ 'message', txt ])

    # create a public chat room.
    # the only point of inserting an announcement into the DB
    # is so that friends can search for it under our ownerfingerprint.
    def make_open(self, roomname):
        c = client.Client(self.nickname, self.server)
        self.roomid = util.randhex(16)
        key = c.finger() + "-room-" + self.roomid
        value = [ roomname, self.roomid ]
        c.put(key, value)
        print("Created chatroom ID %s" % (self.roomid))

    # join an existing group.
    # for now, only open groups.
    def join(self, roomid):
        self.roomid = roomid
        self.go_open()

    # return a list of [ roomname, roomid ]
    # looks at my "known" list for people I know,
    # and then looks for rooms they have created.
    def make_list(self):
        c = client.Client(self.nickname, self.server)

        ret = [ ]
        a = c.range(c.finger() + "-known1-", c.finger() + "-known2-")
        for e in a:
            # [ key, [ 'known', publickey, name ] ]
            othername = e[1][2]
            otherpub = util.unbox(e[1][1])
            other_fingerprint = util.fingerprint(otherpub)
            aa = c.range(other_fingerprint + "-room-", other_fingerprint + "-room-~")
            for ee in aa:
                ret.append( ee[1] )
        
        return ret

if __name__ == '__main__':
    server = ( "127.0.0.1", 10223 )

    if len(sys.argv) == 4 and sys.argv[2] == "--open":
        nickname = sys.argv[1]
        ch = Chat(server, nickname)
        ch.make_open(sys.argv[3])
        ch.go_open()
    elif len(sys.argv) == 4 and sys.argv[2] == "--join":
        nickname = sys.argv[1]
        ch = Chat(server, nickname)
        ch.join(sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[2] == "--list":
        nickname = sys.argv[1]
        ch = Chat(server, nickname)
        ll = ch.make_list()
        for e in ll:
            print(e)
    else:
        sys.stderr.write("Usage: chat nickname --open roomname\n")
        sys.stderr.write("       chat nickname --closed roomname\n")
        sys.stderr.write("       chat nickname --list\n")
        sys.stderr.write("       chat nickname --join roomid\n")
        sys.exit(1)
