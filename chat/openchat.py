#
# chat nickname --new
# chat nickname --list
# chat nickname --join
#
# announcement:
#   key = type=openchat, unique=roomID
#   value = [ roomID ]
# message:
#   key = type=message, unique=roomid-timestamp
#   value = [ timestamp, text ]
#

import sys
import threading
import time

sys.path.append("../client")
import client
sys.path.append("../util")
import util

class Chat:
    # nickname is my nickname for myself, e.g. "rtm".
    def __init__(self, nickname):
        self.nickname = nickname

    # ask the DB service for new messages, once per second.
    def poller(self):
        c = client.Client(self.nickname)
        ts1 = 0
        while True:
            ts2 = int(time.time())
            k1 = self.roomid + "-" + str(ts1)
            k2 = self.roomid + "-" + str(ts2)
            rows = c.range("message", unique = [ k1, k2 ] )
            for row in rows:
                # row.value is [ timestamp, txt ]
                # the nickname is cryptographically bound to
                # the key that signed the message, so that
                # we'll always print the same nickname for the
                # same signer, and always print different nicknames
                # for different signers. that is the sense in
                # which this application is secure.
                timestamp = int(row.value[0])
                txt = row.value[1]
                if timestamp > ts1:
                    ts1 = timestamp
                    if row.nickname != c.nickname():
                        # only print messages that are not from us.
                        print("%s: %s" % (row.nickname, txt))
            time.sleep(1)

    # start a poller(), and read messages from the keyboard.
    def go(self):
        th = threading.Thread(target=lambda : self.poller())
        th.daemon = True
        th.start()
        
        c = client.Client(self.nickname)
        while True:
            sys.stdout.write("%s> " % (self.nickname))
            sys.stdout.flush()
            txt = sys.stdin.readline()
            if txt == '':
                break
            txt = txt[0:-1]

            if len(txt) > 0:
                ts = str(int(time.time()))
                msgid = self.roomid + "-" + ts
                c.put([ ts, txt ],
                      'message',
                      unique=msgid)
                      

    # create a public chat room announcement.
    # the point is so that friends can get a list of chatrooms with --list.
    def make(self):
        c = client.Client(self.nickname)
        self.roomid = util.randhex(16)
        value = [ self.roomid ]
        c.put(value, "openchat", unique=self.roomid)
        print("Created roomID %s" % (self.roomid))
        print("Others should run python3 openchat.py <username> --join %s" % (self.roomid))

    # join an existing group.
    def join(self, roomid):
        self.roomid = roomid
        self.go()

    # return a list of [ roomid ]
    # looks at my "known" list for people I know,
    # and then looks for rooms they have created.
    def make_list(self):
        c = client.Client(self.nickname)

        ret = [ ]
        knowns = c.known_list()
        for e in knowns:
            # e is [ publickey, nickname ]
            aa = c.range("openchat",
                         frm=e[1],
                         unique=[" ", "~"])
            for ee in aa:
                ret.append( ee.value )
        
        return ret

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[2] == "--new":
        nickname = sys.argv[1]
        ch = Chat(nickname)
        ch.make()
        ch.go()
    elif len(sys.argv) == 4 and sys.argv[2] == "--join":
        nickname = sys.argv[1]
        ch = Chat(nickname)
        ch.join(sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[2] == "--list":
        nickname = sys.argv[1]
        ch = Chat(nickname)
        ll = ch.make_list()
        for e in ll:
            print(e)
    else:
        sys.stderr.write("Usage: openchat nickname --new\n")
        sys.stderr.write("       openchat nickname --list\n")
        sys.stderr.write("       openchat nickname --join roomID\n")
        sys.exit(1)
