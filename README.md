The goal is an easy-to-use distributed storage library to help build
multi-user applications. Ideally it would be simple enough so that
readers of e.g. Briggs' Python for Kids could build multi-user chat
and game programs.

The storage model is a single open key/value service, with persistent
data, and range scans.

In order that lots of applications and users be able to share a single
DB service, the library tries to guide applications towards using keys
that are likely to be unique and easy to retrieve via indices.

I'd like to provide useful levels of privacy and authenticity for the
data. To that end, each user has a public/private key pair, and signs
every item inserted into the DB.

The system maintains, separately for each user, a set of
nickname/publickey mappings, so that users and applications can think
in terms of nicknames rather than public keys. The nicknames are not
global; different people might use different nicknames for my public
key. The authentication part of the interface deals in nicknames (as
proxies for public keys).

As yet there's no encryption for privacy.

The main application is multi-user chat. To create a new chatroom:

  cd fug/chat ;
  python3 openchat.py user1 --new

The above will print a roomID. A user can join this chat with:

  python3 openchat.py user2 --join <roomID>

A user can get a list of chatrooms created by known users (users whose
key has already been encountered and for whom a nickname has been
created):

  python3 openchat.py user2 --list
