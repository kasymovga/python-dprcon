#!/usr/bin/env python

from __future__ import print_function

import socket
import re
import sys
import hashlib
import hmac
import random
import time
import select

from functools import wraps

RESPONSE_RE = re.compile(b"\377\377\377n(.*)", re.S)
CHALLENGE_RE = re.compile(b"\377\377\377\377challenge (.*?)(?:$|\0)", re.S)

DEFAULT_BUFFER_SIZE = 32768
DEFAULT_TIMEOUT = 10

try:
    md4 = hashlib.md4
except AttributeError:
    md4 = lambda: hashlib.new('md4')


class RCONError(Exception):
    pass


class RCONConnectionRequiredError(RCONError):
    pass


class RCONAlreadyConnectedError(RCONError):
    pass


class RCONChallengeTimeoutError(RCONError):
    pass


def require_connected(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if not self.connected:
            raise RCONConnectionRequiredError

        return f(self, *args, **kwargs)
    return wrapper


def require_disconnected(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if self.connected:
            raise RCONAlreadyConnectedError

        return f(self, *args, **kwargs)
    return wrapper


def ensure_bytes(s):
    try:  # Python 2
        if isinstance(s, unicode):
            s = s.encode('utf-8')
    except NameError:  # Python 3
        if isinstance(s, str):
            s = s.encode('utf-8')

    assert isinstance(s, bytes)
    return s


class InsecureRCONConnection(object):
    def __init__(self, host, port, password, connect=False, bufsize=DEFAULT_BUFFER_SIZE, timeout=DEFAULT_TIMEOUT):
        self._host = host
        self._port = port
        self._pwd  = ensure_bytes(password)
        self._sock = None

        self.bufsize = bufsize
        self.timeout = timeout

        if connect:
            self.connect()

    def _send(self, s):
        return self._sock.send(s)

    def __del__(self):
        try:
            self.disconnect()
        except Exception:
            pass

    @require_disconnected
    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.connect((self._host, self._port))
        self.timeout = self._timeout

    @property
    def connected(self):
        return self._sock is not None

    @require_connected
    def disconnect(self):
        self._sock.close()
        self._sock = None
        self._addr = None

    @property
    @require_connected
    def local_address(self):
        return "%s:%i" % self._sock.getsockname()

    def make_rcon_message(self, s):
        return b"\377\377\377\377rcon %s %s" % (self._pwd, ensure_bytes(s))

    def translate_rcon_response(self, s):
        try:
            return RESPONSE_RE.findall(s)[0]
        except IndexError:
            return ""

    @require_connected
    def send(self, *s):
        return self._send(b'\0'.join([self.make_rcon_message(a) for a in s]))

    @require_connected
    def read(self, bufsize=None):
        if bufsize is None:
            bufsize = self.bufsize

        return self.translate_rcon_response(self._sock.recv(bufsize))

    @property
    def socket(self):
        return self._sock

    def fileno(self):
        return self._sock.fileno()

    @property
    def timeout(self):
        if not self.connected:
            return self._timeout

        return self._sock.gettimeout()

    @timeout.setter
    def timeout(self, val):
        self._timeout = val

        if not self.connected:
            return self._timeout

        self._sock.settimeout(val)
        return self._sock.gettimeout()


class TimeBasedSecureRCONConnection(InsecureRCONConnection):
    def make_rcon_message(self, line):
        line = ensure_bytes(line)
        mytime = b"%ld.%06d" % (time.time(), random.randrange(1000000))

        return b"\377\377\377\377srcon HMAC-MD4 TIME %s %s %s" % (
            hmac.new(self._pwd, b"%s %s" % (mytime, line), digestmod=md4).digest(),
            mytime, line
        )


class ChallengeBasedSecureRCONConnection(InsecureRCONConnection):
    def __init__(self, host, port, password, connect=False,
                 bufsize=DEFAULT_BUFFER_SIZE, timeout=DEFAULT_TIMEOUT, challenge_timeout=None):
        if challenge_timeout is None:
            challenge_timeout = timeout

        self._challenge = ""
        self.challenge_timeout = challenge_timeout
        self.recvbuf = []

        return super(ChallengeBasedSecureRCONConnection, self).__init__(host, port, password, connect, bufsize)

    def send(self, *s):
        self._challenge = self._recvchallenge()
        return super(ChallengeBasedSecureRCONConnection, self).send(*s)

    def make_rcon_message(self, line):
        line = ensure_bytes(line)
        return b"\377\377\377\377srcon HMAC-MD4 CHALLENGE %s %s %s" % (
            hmac.new(self._pwd, b"%s %s" % (self._challenge, line), digestmod=md4).digest(),
            self._challenge, line
        )

    def translate_challenge_response(self, s):
        try:
            return CHALLENGE_RE.findall(s)[0]
        except IndexError:
            return ""

    def _recvchallenge(self):
        self._send(b"\377\377\377\377getchallenge")
        timeouttime = time.time() + self.challenge_timeout

        while time.time() < timeouttime:
            r = select.select([self._sock], [], [], self.challenge_timeout)[0]

            if self._sock in r:
                s = self._sock.recv(self.bufsize)

                r = self.translate_rcon_response(s)
                if r:
                    self.recvbuf.append(r)
                else:
                    c = self.translate_challenge_response(s)
                    if c:
                        return c

        raise RCONChallengeTimeoutError

    def read(self, bufsize=None):
        if self.recvbuf:
            return self.recvbuf.pop(0)
        return super(ChallengeBasedSecureRCONConnection, self).read(bufsize)


if __name__ == "__main__":
    try:
        input = raw_input
    except NameError:
        pass

    host = input("Server: ")
    port = int(input("Port: "))
    sec  = int(input("Security (as in rcon_secure): "))
    pwd  = input("Password: ")

    try:
        rcon = {
            0:  InsecureRCONConnection,
            1:  TimeBasedSecureRCONConnection,
            2:  ChallengeBasedSecureRCONConnection
        }[sec](host, port, pwd, connect=True)
    except KeyError as e:
        print("Invalid security value:", sec)
        quit(0)

    print("Connected!")
    print("Local address:", rcon.local_address)

    rcon.send("status")

    while True:
        r = select.select([rcon, sys.stdin], [], [])[0]

        if rcon in r:
            s = b"\n" + b"".join([b"> %s\n" % i for i in rcon.read().split(b'\n') if i])
            sys.stdout.write(s.decode('utf-8'))

        if sys.stdin in r:
            rcon.send(sys.stdin.readline()[:-1])
