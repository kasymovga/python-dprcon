#!/usr/bin/env python2

import socket, re, sys, md4, hmac, random, time, select

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
	return wrapper

def requireDisconnected(f):
	def wrapper(self, *args, **kwargs):
		if self.isConnected():
			raise RCONAlreadyConnectedException
		
		return f(self, *args, **kwargs)
	
	wrapper.__doc__ = f.__doc__
	return wrapper 

responseRegexp = re.compile("\377\377\377n(.*)", re.S)
challengeRegexp = re.compile("\377\377\377\377challenge (.*?)(?:$|\0)", re.S)

class InsecureRCONConnection(object):
	def __init__(self, host, port, password, connect=False, bufsize=1024):
		self._host = host
		self._port = port
		self._pwd  = password
		self._sock = None
		self.bufsize = bufsize
		
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
		return "\377\377\377\377rcon %s %s" %(self._pwd, s)
	
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
		
		return self.translateRCONResponse(self._sock.recv(1024))
	
	def getSocket(self):
		return self._sock
	

class TimeBasedSecureRCONConnection(InsecureRCONConnection):
	def makeRCONMessage(self, line):
		mytime = "%ld.%06d" %(time.time(), random.randrange(1000000))
		return "\377\377\377\377srcon HMAC-MD4 TIME %s %s %s" %(
			hmac.new(self._pwd, "%s %s" % (mytime, line), digestmod=md4.new).digest(),
			mytime, line
		)

class ChallengeBasedSecureRCONConnection(InsecureRCONConnection):
	def __init__(self, host, port, password, connect=False, bufsize=1024, timeout=3):
		self.challengeTimeout = timeout
		self.recvbuf = []
		self._challenge = ""
		
		return super(ChallengeBasedSecureRCONConnection, self).__init__(host, port, password, connect, bufsize)
	
	def send(self, *s):
		self._challenge = self._recvchallenge()
		return super(ChallengeBasedSecureRCONConnection, self).send(*s)
	
	def makeRCONMessage(self, line):
		return "\377\377\377\377srcon HMAC-MD4 CHALLENGE %s %s %s" %(
			hmac.new(self._pwd, "%s %s" % (self._challenge, line), digestmod=md4.new).digest(),
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
			r, w, x = select.select([self._sock], [], [])
			
			if self._sock in r:
				s = self._sock.recv(self.bufsize)
				
				r = self.translateRCONResponse(s)
				if r:
					self.recvbuf.append(r)
				else:
					c = self.translateChallengeResponse(s)
					print c
					if c:
						return c
		
		raise RCONChallengeTimeoutException
	
	def read(self, bufsize=None):
		if self.recvbuf:
			return self.recvbuf.pop(0)
		return super(ChallengeBasedSecureRCONConnection, self).read(bufsize)

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
	
	rcon.getSocket().settimeout(1)
	print "Local address:", rcon.getLocalAddress()
	
	while True:
		rcon.send(raw_input("Command: "))
		print "Response follows: "
		
		def getresponse():
			try:
				return rcon.read()
			except socket.error:
				return None
		
		r = getresponse()
		while r is not None:
			sys.stdout.write(r)
			r = getresponse()
	
