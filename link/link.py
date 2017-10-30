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
    # server is e.g. ( "127.0.0.1", 10223 )
    # myname is my name for myself, like "sally".
    def __init__(self, server, myname):
        self.server = server
        self.myname = myname

    # generate the string to read to the other person over
    # the telephone.
    def make_phrase(self):
        s = ""
        for iter in range(0, 5):
            x = Crypto.Random.random.randint(1000, 9999)
            s += str(x)
            s += "-"
        s = s[0:-1]
        return s

    # we want to initiate a link to someone and call them othername.
    def gofirst(self, othername):
        c = client.Client(self.myname, self.server)
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
        pub = c.publickey().exportKey('PEM').hex()
        value = [ 'link1', pub, phrase, message ]
        c.put(phrase, value)

        # check that something else wasn't already there with key=phrase.
        vx = c.get(phrase)
        if vx != value:
            printf("Oops, try again, phrase collision.")
            sys.exit(1)

        print("The phrase is %s" % (phrase))
        print("They should run link.py %s %s %s" % (othername, self.myname, phrase))
        print("Waiting for a reply from %s..." % (othername))

        while True:
            vy = c.get(phrase + "-answer")
            if vy != None:
                break
            time.sleep(1)

        if type(vy) != list or len(vy) != 4:
            print("Phrase entry is wrong in DB.")
            sys.exit(1)

        [ xlink, xpub, xphrase, xmessage ] = vy
        if xlink != 'link2' or xphrase != phrase:
            print("Answering phrase is wrong in DB.")
            sys.exit(1)

        sys.stdout.write("Personal message is \"%s\"; OK? " % (xmessage))
        ok = util.yn()
        if ok != True:
            sys.exit(1)

        # insert into our known list in the DB.
        self.save_known(c, othername, xpub)

    def save_known(self, c, othername, pub):
        # hash the name to produce the key in order to obscure the name.
        # put twice, so that it can be looked up by either
        # name or public key fingerprint.
        # XXX should seal the value.

        print("Remembering user %s." % (othername))

        my_fingerprint = util.fingerprint(c.publickey())
        pub1 = util.unhex(pub)
        pub2 = Crypto.PublicKey.RSA.importKey(pub1)
        other_fingerprint = util.fingerprint(pub2)

        known_value = [ 'known', pub, othername ]
        kk1 = my_fingerprint + '-known1-' + util.hash(other_fingerprint + c.masterrandom.hex())
        c.put(kk1, known_value)
        kk2 = my_fingerprint + '-known2-' + util.hash(othername + c.masterrandom.hex())
        c.put(kk2, known_value)

    # we want to respond to a link from someone and call them othername.
    def gosecond(self, othername, phrase):
        c = client.Client(self.myname, self.server)

        # othername already inserted info under phrase.
        value = c.get(phrase)
        if value == None or type(value) != list or len(value) != 4:
            print("Phrase entry is wrong or missing in DB.")
            sys.exit(1)

        [ xlink, xpub, xphrase, xmessage ] = value
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

        # now insert an answer into the DB.
        # the statement is "the [other] person who knows the phrase has public key X".
        # key is phrase-answer
        pub = c.publickey().exportKey('PEM').hex()
        value = [ 'link2', pub, phrase, mymessage ]
        c.put(phrase + "-answer", value)

        # check that something else wasn't already there with key=phrase.
        vx = c.get(phrase + "-answer")
        if vx != value:
            printf("Phrase collision!")
            sys.exit(1)

        print("%s should see your answer now." % (othername))

        # insert into our known list in the DB.
        self.save_known(c, othername, xpub)

if __name__ == '__main__':
    phrase = None
    if len(sys.argv) == 3:
        myname = sys.argv[1]
        othername = sys.argv[2]
    elif len(sys.argv) == 4:
        myname = sys.argv[1]
        othername = sys.argv[2]
        phrase = sys.argv[3]
    else:
        sys.stderr.write("Usage: link myname othername\n")
        sys.stderr.write("       link myname othername phrase\n")
        sys.exit(1)
    ch = Link(("127.0.0.1", 10223), myname)
    if phrase == None:
        ch.gofirst(othername)
    else:
        ch.gosecond(othername, phrase)
