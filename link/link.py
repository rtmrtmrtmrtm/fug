#
# bluetooth-inspired initial linking with another user.
# generate a random phrase.
# register some key material in DB under that phrase.
# read the phrase to the other user over the phone.
# they fetch the key material from DB, and insert some in return.
#

import sys
import threading
import time
import Crypto.Random.random

sys.path.append("../client")
import client
sys.path.append("../util")
import util

class Link:
    # nickname is my name for myself, like "sally".
    def __init__(self, nickname):
        self.nickname = nickname

    # generate the string to read to the other person over
    # the telephone.
    def make_phrase(self):
        s = ""
        for iter in range(0, 5):
            x = Crypto.Random.random.randint(1000, 9999)
            s += str(x)
            s += "/" # not - since that confuses range()
        s = s[0:-1]
        return s

    # we want to initiate a link to someone and call them othername.
    def gofirst(self, othername):
        c = client.Client(self.nickname)
        phrase = self.make_phrase()

        sys.stdout.write("Enter a personal message for %s: " % (othername))
        sys.stdout.flush()
        message = sys.stdin.readline().strip()

        # what should be in the value we insert with key=phrase?
        # 'link1'
        # our master public key.
        # the phrase.
        # our own name for ourself.
        # our name for the target person.
        # we expect the other party to be able to find
        # our record with a range() with unique=phrase;
        # the range() is needed b/c they don't know fromfinger.
        # XXX the link DB entry should expire quickly.
        pub = c.publickey().exportKey('PEM').hex()
        value = [ 'link1', pub, phrase, message ]
        c.put(value, 'link1', unique=phrase)

        # check that something else wasn't already there with unique=phrase.
        vx = c.range('link1', unique=[ phrase, phrase+"~" ] )
        if len(vx) != 1 or vx[0].value != value or vx[0].nickname != self.nickname:
            print("Oops, try again, phrase collision.")
            sys.exit(1)

        print("The phrase is %s" % (phrase))
        print("They should run link.py %s %s %s" % (othername, self.nickname, phrase))
        print("Waiting for a reply from %s..." % (othername))

        while True:
            vy = c.range('link2', to=self.nickname, unique=[ phrase, phrase+"~" ])
            if len(vy) > 0:
                break
            time.sleep(1)

        if len(vy) != 1 or type(vy[0].value) != list or len(vy[0].value) != 4:
            print("Phrase entry is wrong in DB.")
            sys.exit(1)
            
        if vy[0].key_to != self.nickname:
            print("Reply was not sealed for you.")
            sys.exit(1)

        [ xlink, xpub, xphrase, xmessage ] = vy[0].value
        if xlink != 'link2' or xphrase != phrase:
            print("Answering phrase is wrong in DB.")
            sys.exit(1)

        sys.stdout.write("Personal message is \"%s\"; OK? " % (xmessage))
        ok = util.yn()
        if ok != True:
            sys.exit(1)

        # insert into our known list in the DB.
        c.save_known(othername, xpub)

    # we want to respond to a link from someone and call them othername.
    def gosecond(self, othername, phrase):
        c = client.Client(self.nickname)

        # othername already inserted info under phrase.
        values = c.range('link1', unique=[ phrase, phrase+"~" ])

        if len(values) == 0:
            print("Phrase entry is missing in DB.")
            sys.exit(1)

        if len(values) > 1:
            print("Too many phrase entries in DB!")
            sys.exit(1)

        if type(values[0].value) != list or len(values[0].value) != 4:
            print("Phrase entry is wrong or missing in DB.")
            sys.exit(1)

        [ xlink, xpub, xphrase, xmessage ] = values[0].value
        if xlink != 'link1' or xphrase != phrase:
            print("Phrase has bad content in DB.")
            sys.exit(1)

        sys.stdout.write("Personal message is \"%s\"; OK? " % (xmessage))
        ok = util.yn()
        if ok != True:
            sys.exit(1)

        sys.stdout.write("Enter a personal message for %s: " % (othername))
        sys.stdout.flush()
        mymessage = sys.stdin.readline().strip()

        # insert into our known list in the DB.
        c.save_known(othername, xpub)

        # now insert an answer into the DB.
        # the statement is "the [other] person who knows the phrase has public key X".
        # key is phrase-answer
        pub = util.box(c.publickey())
        value = [ 'link2', pub, phrase, mymessage ]
        c.put(value, 'link2', unique=phrase, to=othername)

        print("%s should see your answer now." % (othername))

    def list(self):
        c = client.Client(self.nickname)
        knowns = c.known_list()
        for e in knowns:
            # e is [ publickey, name ]
            print("%s" % (e[1]))

if __name__ == '__main__':
    phrase = None
    if len(sys.argv) == 3 and sys.argv[2] == "--list":
        ch = Link(sys.argv[1])
        ch.list()
        sys.exit(0)
    elif len(sys.argv) == 3:
        nickname = sys.argv[1]
        othername = sys.argv[2]
    elif len(sys.argv) == 4:
        nickname = sys.argv[1]
        othername = sys.argv[2]
        phrase = sys.argv[3]
    else:
        sys.stderr.write("Usage: link nickname othername\n")
        sys.stderr.write("       link nickname othername phrase\n")
        sys.stderr.write("       link nickname --list\n")
        sys.exit(1)
    ch = Link(nickname)
    if phrase == None:
        ch.gofirst(othername)
    else:
        ch.gosecond(othername, phrase)
