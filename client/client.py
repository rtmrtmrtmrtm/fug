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
import Crypto.Cipher.PKCS1_OAEP
import Crypto.Cipher.AES

sys.path.append("../util")
import util

masterlock = threading.Lock()

# one row from the DB; get() returns one of these,
# and range() returns an array of them.
class Row:
    def __init__(self, value, nickname, key_type, key_to, key_unique):
        self.value = value
        self.nickname = nickname # who inserted it
        self.key_type = key_type # the put() argument
        self.key_to = key_to     # a nickname, the put(to=) argument
        self.key_unique = key_unique # the put(unique=) argument

class Client:

    # nickname is user's human-readable name for her/himself, e.g. "sally".
    def __init__(self, nickname):
        self.nickname_ = nickname

        # self.hostport = ( "fug.rtmrtm.org", 10223 )
        self.hostport = ( "127.0.0.1", 10223 )

        # XXX it's crazy to leave the master private key laying around.
        # ideally a separate agent process that would sign a certificate
        # saying that this app's private key speaks for the master.
        # sets self.masterkey and self.masterrandom
        self._loadMasterKey()

    def nickname(self):
        return self.nickname_

    # to be called by applications.
    # does multiple lowput()s with various sub-key orders.
    # to and frm are nicknames.
    # XXX use something less ambiguous and spoofable than -,
    #     so that client get() and servers can be sure they
    #     are validating the signature of the fromfinger in
    #     the key, to prevent squatting.
    # XXX seal for to's eyes only.
    def put(self, v, typename, to=None, unique=None):
        if to != None:
            tofinger = self.nickname2finger(to)
            to_pub = self.finger2public(tofinger)
            assert not isinstance(to_pub, type(None))
        else:
            tofinger = None
            to_pub = None

        # type-fromfinger-[tofinger]-[unique]
        # for e.g. my own "known" rows
        k = typename + "-" + self.finger()
        if tofinger != None:
            k += "-" + tofinger
        if unique != None:
            k += "-" + unique
        self.lowput(k, v, to_pub)

        # type-unique-fromfinger-[tofinger]
        # for e.g. openchat messages, ordered by unique=timestamp.
        if unique != None:
            k = typename + "-" + unique + "-" + self.finger()
            if tofinger != None:
                k += "-" + tofinger
            self.lowput(k, v, to_pub)

        # type-tofinger-fromfinger-[unique]
        # for e.g. closedchat messages directed at a specific user.
        # the optional stuff has to be at the end...
        if tofinger != None:
            k = typename + "-" + tofinger
            if unique != None:
                k += "-" + unique
            k += "-" + self.finger()
            self.lowput(k, v, to_pub)

    # internal put of specific key.
    # if seal_pub != None, it's an RSA public key; seal v.
    def lowput(self, k, v, seal_pub):
        # generate signature over json of k and v,
        # using master private key and RSASSA-PSS.
        kv = json.dumps([ k, v ])
        h = Crypto.Hash.SHA256.new()
        h.update(kv.encode('utf-8'))
        signer = Crypto.Signature.PKCS1_PSS.new(self.masterkey)
        signature = signer.sign(h)

        myfinger = self.finger()

        if not isinstance(seal_pub, type(None)):
            v = self.seal(seal_pub, v)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "put", k, [ v, signature.hex(), myfinger ] ])
        x = self.recv_json(s)
        s.close()

    # low-level get; does not check signature.
    # returns None, or [ value, signature, fingerprint ]
    def lowlowget(self, k):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "get", k ])
        x = self.recv_json(s)
        s.close()
        return x

    # returns [ hex public-key-encrypted aes key, hex aes-encrypted value ]
    def seal(self, public, value):
        value = bytes(json.dumps(value), 'utf-8')

        # encrypt with a random AES key.
        # then seal the AES key with the public key.
        aeskey = util.randbytes(32)
        iv = util.randbytes(Crypto.Cipher.AES.block_size)
        aescipher = Crypto.Cipher.AES.new(aeskey, Crypto.Cipher.AES.MODE_CFB, iv)
        sealedvalue = iv + aescipher.encrypt(value)

        cipher = Crypto.Cipher.PKCS1_OAEP.new(public)
        sealedkey = cipher.encrypt(aeskey)
        both = [ util.hex(sealedkey),
                 util.hex(sealedvalue) ]
        return both

    def unseal(self, private, both):
        [ sealedkey, iv_sealedvalue ] = both
        sealedkey = util.unhex(sealedkey) # public-key encrypted aes key
        iv_sealedvalue = util.unhex(iv_sealedvalue) # aes-encrypted value

        cipher = Crypto.Cipher.PKCS1_OAEP.new(private)
        aeskey = cipher.decrypt(sealedkey)

        iv = iv_sealedvalue[0:Crypto.Cipher.AES.block_size]
        sealedvalue = iv_sealedvalue[Crypto.Cipher.AES.block_size:]
        
        aescipher = Crypto.Cipher.AES.new(aeskey, Crypto.Cipher.AES.MODE_CFB, iv)
        value = aescipher.decrypt(sealedvalue)

        return json.loads(value.decode('utf-8'))

    # returns a Row (just value and nickname), or None.
    # checks that the key+value is signed by the public
    # key it claims to be signed by.
    # if signer != None, it's a local nickname and the record
    # must have been signed by that nickname.
    # if private != None, unseal (decrypt).
    # XXX check that every k/v is signed by the fromfinger in
    #     the key, since now every key must have a fromfinger
    #     to encourage uniqueness and prevent squatting.
    def lowget(self, k, signer, private):
        v = self.lowlowget(k)
        if v == None:
            # no DB entry for k.
            return None

        # v is [ value, signature, fingerprint ]

        if not isinstance(private, type(None)):
            v[0] = self.unseal(private, v[0])

        if self.check(k, v) == False:
            # signature did not verify at all.
            return None

        nickname = self.finger2nickname(v[2])
        if signer != None:
            if nickname != signer:
                # was not signed by signer.
                return None

        row = Row(v[0], nickname, None, None, None)
        return row

    # dual of put().
    # try various specific low-level keys.
    # to be used only when caller is using the same
    # sub-key info that the corresponding put() used.
    # to and frm are nicknames.
    # returns a Row, so the caller can learn about key and nickname.
    # XXX frm has to be supplied, otherwise there can be more
    #     than one result; if frm isn't known, use range().
    # XXX unseal if needed.
    # XXX to has to be me! otherwise can't unseal.
    def get(self, typename, frm=None, to=None, unique=None):
        if frm != None:
            fromfinger = self.nickname2finger(frm)
        else:
            fromfinger = None

        if to != None:
            assert to == self.nickname() # since we need private key
            tofinger = self.finger()
            to_priv = self.masterkey
        else:
            tofinger = None
            to_priv = None

        # type-fromfinger-[tofinger]-[unique]
        # for e.g. my own "known" rows
        if fromfinger != None:
            k = typename + "-" + fromfinger
            if tofinger != None:
                k += "-" + tofinger
            if unique != None:
                k += "-" + unique
            row = self.lowget(k, frm, to_priv)
            if row != None:
                row.key_type = typename
                row.key_unique = unique
                row.key_to = to
            return row

        # type-unique-fromfinger-[tofinger]
        # for e.g. openchat messages, ordered by unique=timestamp.
        if unique != None and fromfinger != None:
            k = typename + "-" + unique + "-" + fromfinger
            if tofinger != None:
                k += "-" + tofinger
            row = self.lowget(k, frm, to_priv)
            if row != None:
                row.key_type = typename
                row.key_unique = unique
                row.key_to = to
            return row

        # type-tofinger-fromfinger-[unique]
        # for e.g. closedchat messages directed at a specific user.
        # the optional stuff has to be at the end...
        if tofinger != None and fromfinger != None:
            k = typename + "-" + tofinger + "-" + fromfinger
            if unique != None:
                k += "-" + unique
            row = self.lowget(k, frm, to_priv)
            if row != None:
                row.key_type = typename
                row.key_unique = unique
                row.key_to = to
            return row

        sys.stderr.write("get() can't guess key; %s %s %s %s\n" % (typename,
                                                                   frm,
                                                                   to,
                                                                   unique))
        assert False

    # check the signature on a k/v fetched from DB.
    # v is as returned by lowlowget: [ value, signature, fingerprint ]
    # XXX check that the fingerprint matches the relevant
    #     field in the key.
    def check(self, k, v):
        finger = v[2]

        public = self.finger2public(finger)
        if isinstance(public, type(None)):
            # couldn't find finger in DB,
            # or it didn't match the public key.
            return False
        
        # v is [ value, signature, fingerprint ]

        # check the signature
        kv = json.dumps([ k, v[0] ])
        h = Crypto.Hash.SHA256.new()
        h.update(kv.encode('utf-8'))
        verifier = Crypto.Signature.PKCS1_PSS.new(public)
        ok = verifier.verify(h, util.unhex(v[1]))
        if ok == False:
            return False

        return True

    # returns list of Row.
    # if signer!=None, only return lines signed by that nickname.
    # *_col (if not None) say which key columns hold various things,
    # used to create a Row.
    def lowrange(self, key1, key2, signer, type_col, to_col, unique_col, private):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.hostport)
        self.send_json(s, [ "range", key1, key2 ])
        x = self.recv_json(s)
        s.close()

        x1 = [ ]
        for xx in x:
            # xx is [ key, [ value, signature, fingerprint ] ]
            
            if not isinstance(private, type(None)):
                xx[1][0] = self.unseal(private, xx[1][0])

            if self.check(xx[0], xx[1]):
                nickname = self.finger2nickname(xx[1][2])
                if signer == None or signer == nickname:
                    key_type = None
                    key_to = None
                    key_unique = None
                    keyvec = xx[0].split('-') # XXX spoofable!
                    if type_col != None:
                        key_type = keyvec[type_col]
                    if to_col != None:
                        key_to = keyvec[to_col]
                        # XXX Row.key_to wants a nickname!
                        # but it's always to=us...
                        assert key_to == self.finger()
                        key_to = self.nickname()
                    if unique_col != None:
                        key_unique = keyvec[unique_col]
                    row = Row(xx[1][0],
                              nickname,
                              key_type,
                              key_to,
                              key_unique)
                    x1.append(row)
        return x1

    # only some kinds of range scans are supported,
    # implied by which argument is a two-element list.
    # type-fromfinger-[unique1,unique2] (for e.g. "known" rows).
    # type-[unique1,unique2]-fromfinger (for e.g. openchat messages).
    #
    # returns a list of Row objects, each with:
    #   .value, .nickname, .key_type, .key_to, .key_unique
    #
    # how to scan a type-fromfinger-unique or type-unique-fromfinger
    #   collection is tricky. put() always populates both if it can.
    #   range() decides which to scan based on whether frm is set;
    #   if it is, it only looks at type-fromfinger-[u1,u2].
    # XXX check that fromfinger in resulting keys signed each row.
    # XXX unseal.
    # XXX the returned keys won't be meaningful, should translate
    #     back to argument scheme.
    def range(self, type, frm=None, to=None, unique=None):
        if frm != None:
            fromfinger = self.nickname2finger(frm)
        else:
            fromfinger = None

        if to != None:
            assert to == self.nickname() # since we need private key
            tofinger = self.finger()
            to_priv = self.masterkey
        else:
            tofinger = None
            to_priv = None

        # type-fromfinger-[tofinger]-[unique1,unique2] (for e.g. "known" rows).
        if fromfinger != None and isinstance(unique, list) and len(unique) == 2:
            to_col = None
            unique_col = 2
            k1 = type + "-" + fromfinger
            if tofinger != None:
                k1 += "-" + tofinger
                to_col = 2
                unique_col += 1
            k1 += "-" + unique[0]
            k2 = type + "-" + fromfinger
            if tofinger != None:
                k2 += "-" + tofinger
            k2 += "-" + unique[1]
            a = self.lowrange(k1, k2, frm, 0, to_col, unique_col, to_priv)
            return a

        # type-[unique1,unique2]-fromfinger-[tofinger] (for e.g. openchat messages).
        if fromfinger == None and isinstance(unique, list) and len(unique) == 2:
            if to_priv != None:
                to_col = 3
            else:
                to_col = None
            k1 = type + "-" + unique[0]
            k2 = type + "-" + unique[1]
            a = self.lowrange(k1, k2, None, 0, to_col, 1, to_priv)
            return a

        sys.stderr.write("range() can't guess scheme; %s %s %s %s\n" % (type,
                                                                        frm,
                                                                        to,
                                                                        unique))
        assert False

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

        self.put([ self.nickname(), util.box(self.publickey()) ],
                 "finger")

    # return our master public key,
    # as a Crypto _RSAobj.
    def publickey(self):
        return self.masterkey.publickey()

    # fingerprint of our master public key.
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
        k = "finger-" + finger
        v = self.lowlowget(k)
        if v == None:
            return None
        else:
            # v is [ [ nickname, boxed public key ], signature, fingerprint ]
            if self.check(k, v) == False:
                return None
            nickname = v[0][0]
            nickname = self.save_known(nickname, v[0][1])
            return nickname

    # given a local nickname that's already been established,
    # return its fingerprint.
    def nickname2finger(self, nickname):
        nnv = self.known_nickname(nickname)
        assert nnv != None
        [ pub, junk ] = nnv
        finger = util.fingerprint(util.unbox(pub))
        return finger

    # given a public key fingerprint, return an (unboxed) public key.
    # returns Crypto _RSAobj, or None.
    # verifies that the fingerprint matches the key.
    def finger2public(self, finger):
        # retrieve the fingerprint's public key from the DB.
        pkv = self.lowlowget("finger-" + finger)
        if pkv == None:
            # no entry for the fingerprint,
            return None
        
        # pkv [ [ nickname, boxed public key ], signature, fingerprint ]

        # check that the fingerprint matches the public key.
        public = util.unbox(pkv[0][1])
        f1 = util.fingerprint(public)
        if f1 != finger:
            print("client.check(): fingerprint mismatch")
            return None

        return public

    # save a nickname/fingerprint relationship that we've learned,
    # so that in future we always use the same nickname for
    # the corresponding public key.
    # pub should be boxed.
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

        h1 = util.hash(other_fingerprint + self.masterrandom.hex())
        self.put(known_value,
                 "known1",
                 unique=h1)

        h2 = util.hash(nickname + self.masterrandom.hex())
        self.put(known_value,
                 "known2",
                 unique=h2)

        return nickname

    # do we know about the indicated key fingerprint?
    # return [ boxedpublickey, nickname ] or None
    def known_finger(self, finger):
        if finger == self.finger():
            return [ util.box(self.publickey()), self.nickname() ]
        h = util.hash(finger + self.masterrandom.hex())
        row = self.get("known1", frm=self.nickname(), unique=h)
        if row != None:
            return row.value
        else:
            return None

    # do we know about the indicated nickname?
    # return [ boxedpublickey, nickname ] or None
    def known_nickname(self, nickname):
        if nickname == self.nickname():
            return [ util.box(self.publickey()), self.nickname() ]
        h = util.hash(nickname + self.masterrandom.hex())
        row = self.get("known2", frm=self.nickname(), unique=h)
        if row != None:
            return row.value
        else:
            return None

    # fetch and return full "known" list.
    # each entry is [ boxedpublickey, nickname ]
    def known_list(self):
        ret = [ ]
        rows = self.range("known1", frm=self.nickname(), unique=[" ", "~"])
        for row in rows:
            # row.value is [ boxedpublickey, nickname ]
            ret.append( row.value )
        return ret


def tests():
    name1 = util.randhex(6)
    name2 = util.randhex(6)
    name3 = util.randhex(6)
    c1 = Client(name1)
    c2 = Client(name2)
    c3 = Client(name3)

    # can I see my own puts?
    # type-fromfinger
    c1.put("v1", "type1")
    assert c1.get("type1", frm=name1).value == "v1"
    c1.put(["v1"], "type1list")
    assert c1.get("type1list", frm=name1).value == ["v1"]
    # type-fromfinger-unique
    c1.put("v2", "type1", unique="uuu2")
    c1.put("v3", "type1", unique="uuu3")
    assert c1.get("type1", frm=name1, unique="uuu2").value == "v2"
    assert c1.get("type1", frm=name1, unique="uuu3").value == "v3"

    # make c1 and c2 know about each other by nickname.
    c1.save_known(name2, util.box(c2.publickey()))
    c2.save_known(name1, util.box(c1.publickey()))

    # check that c1 and c2 know about each other.
    assert c1.finger2nickname(c1.finger()) == c1.nickname()
    assert c1.finger2nickname(c2.finger()) == c2.nickname()
    assert c2.finger2nickname(c1.finger()) == c1.nickname()
    assert c2.finger2nickname(c2.finger()) == c2.nickname()
    assert c1.nickname2finger(c1.nickname()) == c1.finger()
    assert c1.nickname2finger(c2.nickname()) == c2.finger()
    assert c2.nickname2finger(c1.nickname()) == c1.finger()
    assert c2.nickname2finger(c2.nickname()) == c2.finger()

    # can c2 see c1's puts?
    assert c2.get("type1", frm=name1).value == "v1"
    assert c2.get("type1", frm=name1, unique="uuu2").value == "v2"
    assert c2.get("type1", frm=name1, unique="uuu3").value == "v3"

    # implicitly tests range().
    kn1 = c1.known_list()
    # kn1 is [ [ public, nickname ], ... ]
    assert len(kn1) == 1
    assert c2.nickname() in [ x[1] for x in kn1 ]

    # range() type-fromfinger-[unique1,unique2]
    c1.put("v4"+name1, "type2", unique="aaa")
    c1.put("v5"+name1, "type2", unique="bbb")
    c1.put("v6"+name1, "type2", unique="ccc")
    c1.put("v7"+name1, "type2", unique="ddd")
    assert len(c1.range("type2", frm=c1.nickname(), unique=[ "b", "c~" ])) == 2
    assert len(c2.range("type2", frm=c1.nickname(), unique=[ "b", "c~" ])) == 2

    # range() type-[unique1,unique2]-fromfinger
    a = c2.range("type2", frm=None, unique=[ "b", "c~" ])
    assert "v4"+name1 not in [ x.value for x in a ]
    assert "v5"+name1 in [ x.value for x in a ]
    assert "v6"+name1 in [ x.value for x in a ]
    assert "v7"+name1 not in [ x.value for x in a ]

    # sealed (encrypted) put/get
    v8 = "v8" + name1
    c1.put(v8, "type3", unique="888", to=c2.nickname())
    row = c2.get("type3", unique="888", frm=c1.nickname(), to=c2.nickname())
    assert row.key_to == c2.nickname()
    assert row.nickname == c1.nickname()
    assert row.value == v8

    c1.put(["v9"], "type3", unique="999", to=c2.nickname())
    assert c2.get("type3", unique="999", frm=c1.nickname(), to=c2.nickname()).value == ["v9"]

    # sealed range()
    a = c2.range("type3", unique=["800","900"], frm=c1.nickname(), to=c2.nickname())
    assert len(a) == 1
    assert v8 in [ x.value for x in a ]
    assert a[0].key_to == c2.nickname()
    assert a[0].nickname == c1.nickname()

if __name__ == '__main__':
    tests()
