#
# chat nickname --new 
# chat nickname --list
# chat nickname --join
#
# announcement:
#   needed so others know who should sign the participant list entries.
#   anyone can cook up any roomID! and insert participant entries!
#   key = "room"-ownerfinger-roomID
#   value = 
# closed participant list entry:
#   key = "participant"-ownerfinger-roomID-participantfinger
#   value = [ participantfinger ]
# closed message (one per recipient):
#   key = "message"-roomid-fromfingerprint-tofingerprint-timestamp
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
    # nickname is my nickname for myself, e.g. "rtm".
    def __init__(self, nickname, othernickname):
        self.nickname = nickname
        self.other = othernickname

    # ask the DB service for new messages, once per second.
    def poller(self):
        c = client.Client(self.nickname)
        ts1 = 0
        while True:
            ts2 = int(time.time())
            k1 = str(ts1)
            k2 = str(ts2)
            # XXX should do one range() per participant.
            rows = c.range("cmessage", frm=self.other, to=self.nickname, unique=[ k1, k2 ] )
            for row in rows:
                # row.value is [ timestamp, txt ]
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
            sys.stdout.write("%s-%s> " % (self.nickname, self.other))
            sys.stdout.flush()
            txt = sys.stdin.readline()
            if txt == '':
                break
            txt = txt[0:-1]

            if len(txt) > 0:
                ts = str(int(time.time()))
                # XXX should somehow include chat instance ID,
                # XXX if more than one participant, once for each.
                c.put([ ts, txt ],
                      'cmessage',
                      to=self.other,
                      unique=ts)
                      
if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[2] == "--new":
        mynickname = sys.argv[1]
        othernickname = sys.argv[3]
        ch = Chat(mynickname, othernickname)
        ch.go()
    else:
        sys.stderr.write("Usage: closedchat nickname --new othernickname\n")
        sys.exit(1)
