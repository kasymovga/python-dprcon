#!/usr/bin/env python2

import socket, re, sys, hashlib, hmac, random, time, select

responseRegexp = re.compile("\377\377\377n(.*)", re.S)
challengeRegexp = re.compile("\377\377\377\377challenge (.*?)(?:$|\0)", re.S)

defaultBufferSize = 32768
defaultTimeout = 10

try:
    md4 = hashlib.md4
except AttributeError:
    md4 = lambda: hashlib.new('md4')

class RCONException(Exception):
	pass

class RCONConnectionRequiredException(RCONException):
	pass

class RCONAlreadyConnectedException(RCONException):
	pass

class RCONChallengeTimeoutException(RCONException):
	pass

def requireConnected(f):
	def wrapper(self, *args, **kwargs):
		if not self.isConnected():
			raise RCONConnectionRequiredException
		
		return f(self, *args, **kwargs)
	
	wrapper.__doc__ = f.__doc__
	wrapper.__name__ = f.__name__
	return wrapper

def requireDisconnected(f):
	def wrapper(self, *args, **kwargs):
		if self.isConnected():
			raise RCONAlreadyConnectedException
		
		return f(self, *args, **kwargs)
	
	wrapper.__doc__ = f.__doc__
	wrapper.__name__ = f.__name__
	return wrapper 

class InsecureRCONConnection(object):
	def __init__(self, host, port, password, connect=False, bufsize=defaultBufferSize, timeout=None):
		self._host = host
		self._port = port
		self._pwd  = password
		self._sock = None
		
		self.setBufsize(bufsize)
		self.setTimeout(timeout)
		
		if connect:
			self.connect()
	
	def __del__(self):
		try:
			self.disconnect()
		except RCONAlreadyConnectedException:
			pass
	
	@requireDisconnected
	def connect(self):
		self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self._sock.connect((self._host, self._port))
		self.setTimeout(self.timeout)

	def isConnected(self):
		return self._sock is not None
	
	@requireConnected
	def disconnect(self):
		self._sock.close()
		self._sock = None
		self._addr = None
	
	@requireConnected
	def getLocalAddress(self):
		return "%s:%i" % self._sock.getsockname()
	
	def makeRCONMessage(self, s):
		return "\377\377\377\377rcon %s %s" %(self._pwd, s.decode('utf-8'))
	
	def translateRCONResponse(self, s):
		try:
			return responseRegexp.findall(s)[0]
		except IndexError:
			return ""
	
	@requireConnected
	def send(self, *s):
		return self._sock.send('\0'.join([self.makeRCONMessage(a) for a in s]))
	
	@requireConnected
	def read(self, bufsize=None):
		if bufsize is None:
			bufsize = self.bufsize
		
		return self.translateRCONResponse(self._sock.recv(bufsize))
	
	def getSocket(self):
		return self._sock
	
	def fileno(self):
		return self._sock.fileno()

	def getTimeout(self):
		if not self.isConnected():
			return self.timeout
		
		return self._sock.gettimeout()
		
	def setTimeout(self, val):
		if not self.isConnected():
			self.timeout = val
			return self.timeout
		
		self._sock.settimeout(val)
		return self._sock.gettimeout()
	
	def getBufsize(self):
		return self.bufsize
	
	def setBufsize(self, val):
		self.bufsize = int(val)
		return self.bufsize

class TimeBasedSecureRCONConnection(InsecureRCONConnection):
	def makeRCONMessage(self, line):
		mytime = "%ld.%06d" %(time.time(), random.randrange(1000000))
		return "\377\377\377\377srcon HMAC-MD4 TIME %s %s %s" %(
			hmac.new(self._pwd, "%s %s" % (mytime, line.decode('utf-8')), digestmod=md4).digest(),
			mytime, line
		)

class ChallengeBasedSecureRCONConnection(InsecureRCONConnection):
	def __init__(self, host, port, password, connect=False, bufsize=defaultBufferSize, timeout=defaultTimeout, challengeTimeout=defaultTimeout):
		self._challenge = ""
		self.setChallengeTimeout(challengeTimeout)
		self.recvbuf = []
		
		return super(ChallengeBasedSecureRCONConnection, self).__init__(host, port, password, connect, bufsize)
	
	def send(self, *s):
		self._challenge = self._recvchallenge()
		return super(ChallengeBasedSecureRCONConnection, self).send(*s)
	
	def makeRCONMessage(self, line):
		return "\377\377\377\377srcon HMAC-MD4 CHALLENGE %s %s %s" %(
			hmac.new(self._pwd, "%s %s" % (self._challenge, line.decode('utf-8')), digestmod=md4).digest(),
			self._challenge, line
		)
	
	def translateChallengeResponse(self, s):
		try:
			return challengeRegexp.findall(s)[0]
		except IndexError:
			return ""
		
	def _recvchallenge(self):
		self._sock.send("\377\377\377\377getchallenge");
		timeouttime = time.time() + self.challengeTimeout
		
		while time.time() < timeouttime:
			r = select.select([self._sock], [], [], self.challengeTimeout)[0]
			
			if self._sock in r:
				s = self._sock.recv(self.bufsize)
				
				r = self.translateRCONResponse(s)
				if r:
					self.recvbuf.append(r)
				else:
					c = self.translateChallengeResponse(s)
					if c:
						return c
		
		raise RCONChallengeTimeoutException
	
	def read(self, bufsize=None):
		if self.recvbuf:
			return self.recvbuf.pop(0)
		return super(ChallengeBasedSecureRCONConnection, self).read(bufsize)
	
	def getChallengeTimeout(self):
		return self.challengeTimeout
	
	def setChallengeTimeout(self, val):
		self.challengeTimeout = float(val)
		return self.challengeTimeout

if __name__ == "__main__":
	host = raw_input("Server: ")
	port = int(raw_input("Port: "))
	sec  = int(raw_input("Security (as in rcon_secure): "))
	pwd  = raw_input("Password: ")
	
	try:
		rcon = {
			0:	InsecureRCONConnection,
			1:	TimeBasedSecureRCONConnection,
			2:	ChallengeBasedSecureRCONConnection
		}[sec](host, port, pwd, connect=True)
	except KeyError as e:
		print "Invalid security value:", sec
		quit(0)

	print "Connected!"
	print "Local address:", rcon.getLocalAddress()
	
	rcon.send("status")
	
	while True:
		r = select.select([rcon, sys.stdin], [], [])[0]
		
		if rcon in r:
			sys.stdout.write("\n" + "".join(["> %s\n" % i for i in rcon.read().split('\n') if i]))
		
		if sys.stdin in r:
			rcon.send(sys.stdin.readline()[:-1])
