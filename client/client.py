#
# client library
# includes a bunch of useful stuff beyond basic server interaction.
#
# common format of all data inserted into DB for put(key, value):
#   dbkey = key
#   dbvalue = [ value, sign(key + value), myfingerprint ]
#
# format of a fingerprint -> publickey record:
#   key = "finger-" + my public key fingerprint
#   value = [ nickname, public key ]
#
# format of "known user" records that bind a local
# nickname to a public key fingerprint.
#  key = "known1-" + myfinger + hash(otherfinger)
#  key = "known2-" + myfinger + hash(othernickname)
#  value = [ publickey, nickname ]
#

import socket
import json
import struct
import time
import re
import sys
import fcntl
import threading
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_PSS

sys.path.append("../util")
import util

masterlock = threading.Lock()

class Client:

    # nickname is user's human-readable name for her/himself, e.g. "sally".
    # hostport is server address, e.g. ( "127.0.0.1", 10223 )
    def __init__(self, nickname, hostport):
        self.nickname_ = nickname
        self.hostport = hostport

        # XXX it's crazy to leave the master private key laying around.
        # ideally a separate agent process that would sign a certificate
        # saying that this app's private key speaks for the master.
        # sets self.masterkey and self.masterrandom
        self._loadMasterKey()

    def nickname(self):
        return self.nickname_

    # XXX should take an argument indicating who (if anyone)
    # we want to be able to read the k/v -- i.e. how to
    # seal it.
    def put(self, k, v):
        # generate signature over json of k and v,
        # using master private key and RSASSA-PSS.
        kv = json.dumps([ k, v ])
        h = Crypto.Hash.SHA256.new()
        h.update(kv.encode('utf-8'))
        signer = Crypto.Signature.PKCS1_PSS.new(self.masterkey)
        signature = signer.sign(h)

        myfinger = self.finger()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "put", k, [ v, signature.hex(), myfinger ] ])
        x = self.recv_json(s)
        s.close()

    # low-level get; does not check signature.
    # returns None, or [ value, signature, fingerprint ]
    def lowget(self, k):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "get", k ])
        x = self.recv_json(s)
        s.close()
        return x

    # None, or a value.
    # checks that the key+value is signed by the public
    # key it claims to be signed by.
    # if signer != None, it's a local nickname and the record
    # must have been signed by that nickname.
    def get(self, k, signer):
        v = self.lowget(k)
        if v == None:
            # no DB entry for k.
            return None

        # v is [ value, signature, fingerprint ]

        if self.check(k, v) == False:
            # signature did not verify at all.
            return None

        if signer != None:
            nn = self.finger2nickname(v[2])
            if nn != signer:
                # was not signed by signer.
                return None

        return v[0]

    # check the signature on a k/v fetched from DB.
    # v is as returned by lowget.
    def check(self, k, v):
        finger = v[2]

        # retrieve the fingerprint's public key from the DB.
        pkv = self.lowget("finger-" + finger)
        if pkv == None:
            # no entry for the fingerprint,
            # so pretend the DB entry is entirely missing.
            return False
        
        # v is [ value, signature, fingerprint ]
        # pkv [ [ nickname, public key ], signature, fingerprint ]

        # check that the fingerprint matches the public key.
        public = util.unbox(pkv[0][1])
        f1 = util.fingerprint(public)
        if f1 != finger:
            print("client.check(): fingerprint mismatch")
            return False

        # check the signature
        kv = json.dumps([ k, v[0] ])
        h = Crypto.Hash.SHA256.new()
        h.update(kv.encode('utf-8'))
        verifier = Crypto.Signature.PKCS1_PSS.new(public)
        ok = verifier.verify(h, util.unhex(v[1]))
        if ok == False:
            return False

        return True

    # list of [ key, value, nickname ]
    # each nickname is the local nickname for the
    # public key that signed the row.
    # if signer!=None, only return lines signed by that nickname.
    def range(self, key1, key2, signer):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "range", key1, key2 ])
        x = self.recv_json(s)
        s.close()

        x1 = [ ]
        for xx in x:
            # xx is [ key, [ value, signature, fingerprint ] ]
            if self.check(xx[0], xx[1]):
                nn = self.finger2nickname(xx[1][2])
                if signer == None or signer == nn:
                    x1.append( [ xx[0], xx[1][0], nn ] )
        return x1

    def send_json(self, s, obj):
        txt = bytes(json.dumps(obj), 'utf-8')
        s.sendall(struct.pack("I", len(txt)) + txt)
            
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

    ###
    ### below are methods for authentication, signing, and sealing.
    ### perhaps they should be somewhere else.
    ###

    # given the local user's nickname, either load public/private
    # key from a file, or create a key pair and store it.
    # the latter creates a new user identity.
    # returns a Crypto RSA key object.
    def _loadMasterKey(self):
        dir = "/tmp"

        # avoid simultaneous master key creations.
        # fcntl.lock() only seems to work between
        # different processes -- two threads in the
        # same process are both allowed to hold a
        # fcntl lock.
        f = open(dir + "/fug-lock", "w")
        fcntl.lockf(f, fcntl.LOCK_EX)

        # guard against threads in this process too.
        masterlock.acquire()

        self.__loadMasterKey(dir)

        f.close()
        masterlock.release()

    def __loadMasterKey(self, dir):

        nickname1 = re.sub(r'[^a-zA-Z0-9-]', 'x', self.nickname())
        keyfile = dir + "/" + 'fug-master-%s.pem' % (nickname1)
        f = None
        try:
            f = open(keyfile, 'rb')
        except:
            pass

        if f != None:
            kx = f.read()
            f.close()
            key = Crypto.PublicKey.RSA.importKey(kx)
        else:
            print("creating new master key for %s" % (self.nickname()))
            key = Crypto.PublicKey.RSA.generate(2048)
            f = open(keyfile, "wb")
            f.write(key.exportKey('PEM'))
            f.close()

        self.masterkey = key

        keyfile = dir + "/" + 'fug-random-%s.pem' % (nickname1)
        f = None
        try:
            f = open(keyfile, 'rb')
        except:
            pass

        if f != None:
            rrr = f.read()
            f.close()
        else:
            print("creating new master randomness for %s" % (self.nickname()))
            rrr = Crypto.Random.new().read(32)
            f = open(keyfile, "wb")
            f.write(rrr)
            f.close()

        # type is bytes
        self.masterrandom = rrr

        self.put("finger-" + self.finger(), [ self.nickname(), util.box(self.publickey()) ] )

    # return the master public key.
    def publickey(self):
        return self.masterkey.publickey()

    # fingerprint of my master public key.
    # returns a hex str.
    def finger(self):
        return util.fingerprint(self.publickey())

    # look up a fingerprint in the DB, return nickname.
    # returns a permanent local nickname, so that
    # the user can be assured that a given name always
    # refers to the same user.
    def finger2nickname(self, finger):
        if finger == self.finger():
            return self.nickname()
        x = self.known_finger(finger)
        if x != None:
            return x[1]
        x = self.get("finger-" + finger, None)
        if x == None:
            return None
        else:
            # x is [ nickname, public key ]
            nickname = x[0]
            nickname = self.save_known(nickname, x[1])
            return nickname

    # save a nickname/fingerprint relationship that we've learned,
    # so that in future we always use the same nickname for
    # the corresponding public key.
    # XXX should seal these so only inserting user can read them.
    # returns the nickname, possibly different.
    def save_known(self, nickname, pub):
        # hash the nickname to produce the key in order to obscure the name.
        # put twice, so that it can be looked up by either
        # name or public key fingerprint.

        x = self.known_nickname(nickname)
        if x != None:
            # we've already saved a public key for this nickname.
            # or we ourselves are using this nickname.
            pub1 = x[0]
            if pub1 == pub:
                # it's the same user.
                print("Nickname %s is already known; same user." % (nickname))
                return
            # choose a different, unused, nickname.
            onickname = nickname
            while True:
                m = re.match(r'^(.*)-([0-9]+)$', nickname)
                if m == None:
                    nickname = nickname + "-1"
                else:
                    nickname = m.group(1) + "-" + str(int(m.group(2)) + 1)
                if self.known_nickname(nickname) == None:
                    break
            print("Nickname %s already in use; substituting  %s." % (onickname, nickname))

        print("Remembering nickname %s." % (nickname))

        pub2 = util.unbox(pub)
        other_fingerprint = util.fingerprint(pub2)

        known_value = [ pub, nickname ]

        kk1 = "known1-" + self.finger() + util.hash(other_fingerprint + self.masterrandom.hex())
        self.put(kk1, known_value)

        kk2 = "known2-" + self.finger() + util.hash(nickname + self.masterrandom.hex())
        self.put(kk2, known_value)

        return nickname

    # do we know about the indicated key fingerprint?
    # return [ publickey, nickname ] or None
    def known_finger(self, finger):
        if finger == self.finger():
            return [ util.box(self.publickey()), self.nickname() ]
        key = "known1-" + self.finger() + util.hash(finger + self.masterrandom.hex())
        # XXX assert that we signed the k/v pair!
        x = self.get(key, self.nickname())
        return x

    # do we know about the indicated nickname?
    # return [ publickey, nickname ] or None
    def known_nickname(self, nickname):
        if nickname == self.nickname():
            return [ util.box(self.publickey()), self.nickname() ]
        key = "known2-" + self.finger() + util.hash(nickname + self.masterrandom.hex())
        # XXX assert that we signed the k/v pair!
        x = self.get(key, self.nickname())
        return x

    # fetch and return full "known" list.
    # each entry is [ publickey, nickname ]
    def known_list(self):
        ret = [ ]
        rows = self.range("known1-" + self.finger(),
                          "known1-" + self.finger() + "~",
                          self.nickname())
        for row in rows:
            # row is [ key, [ publickey, nickname ] ]
            ret.append(row[1])
        return ret


def tests():
    cno = Client("client-test-no", ( "127.0.0.1", 10223 ))

    c = Client("client-test", ( "127.0.0.1", 10223 ))

    c.put("a", "aa")
    c.put("a1", "old")
    c.put("a1", "aa1")
    c.put("a2", "aa2")
    c.put("a3", "aa3")
    c.put("b", "bb")
    assert c.get("a1", c.nickname()) == "aa1"
    assert c.get("a1", None) == "aa1"

    assert c.get("a", "wrongowner") == None
    assert c.get("a", "client-test-no") == None
    assert c.get("nothere", c.nickname()) == None
    assert c.get("nothere", None) == None

    z = c.range("a", "a2", c.nickname())
    # [ [ 'a1', 'aa1' ], [ 'a', 'aa' ] ]
    assert len(z) == 2
    assert [ 'a1', 'aa1', 'client-test' ] in z
    assert [ 'a', 'aa', 'client-test' ] in z

    z = c.range("a", "a2", None)
    assert len(z) == 2

    z = c.range("a", "a2", "client-test-no")
    assert len(z) == 0

if __name__ == '__main__':
    tests()
