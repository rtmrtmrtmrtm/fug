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

    # we want to link to someone and call them othername.
    def go(self, othername):
        c = client.Client(self.myname, self.server)
        phrase = self.make_phrase()

        # what should be in the value we insert with key=phrase?
        # 'link'
        # our master public key.
        # the phrase.
        # our own name for ourself.
        # our name for the target person.
        pub = c.publickey().exportKey('PEM').hex()
        value = [ 'link', pub, phrase, self.myname, othername ]
        c.put(phrase, value)

        # check that something else wasn't already there with key=phrase.
        vx = c.get(phrase)
        if vx != value:
            printf("Oops, try again, phrase collision.")
            sys.exit(1)

        print("The phrase is %s" % (phrase))
        print("They should run link.py %s %s %s" % (othername, self.myname, phrase))

if __name__ == '__main__':
    if len(sys.argv) == 3:
        myname = sys.argv[1]
        othername = sys.argv[2]
    else:
        sys.stderr.write("Usage: link myname othername\n")
        sys.stderr.write("       link myname othername phrase\n")
        sys.exit(1)
    ch = Link(("127.0.0.1", 10223), myname)
    ch.go(othername)
