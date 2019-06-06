import glob
import hmac
import hashlib
import sys
import re
import ntpath

LAU_KEY = b'Abcdef1234567890Abcdef1234567890'

def split_message(msg):
	m = re.search(r'{S:.*}', msg)
	if m:
		s = m.group(0)
		return msg.replace(s, ''), s 
	else:
		return msg, ''

def find_digest(msg):
	m = re.search(r'{MDG:\w+}', msg)
	if m: return m.group(0)

def sign(msg):
	dig = hmac.new(LAU_KEY, msg=msg, digestmod=hashlib.sha256).digest()
	return dig.hex().upper()

def add_digest(s,dig):
	if s:
		return '{' + s[1:-1] + '{MDG:' + dig + '}}'
	else:
		return '{S:{MDG:' + dig + '}}'
		
def proc_message(msg):
	msg, s = split_message(msg)
	dig = sign(msg.encode())
	d = find_digest(s)
	if d:
		print(d, dig)
		s = s.replace(d,'')
	msg += add_digest(s, dig)
	return msg.encode()

def read_dos_pcc(fname):
	msg=b''
	with open(fname,'rb') as fi:
		while True:
			ch = fi.read(1)
			if ch==b'\x01':
				msg=b''
			elif ch==b'\x03':
				yield msg.decode()
				#proc_message(msg.decode())
			else:
				msg += ch
			if not ch: break
			
def read_rje(fname):
	msg=b''
	with open(fname,'rb') as fi:
		while True:
			ch = fi.read(1)
			if not ch or ch==b'$':
				yield msg.decode()
				#proc_message(msg.decode())
				msg = b''
			else:
				msg += ch
			if not ch: break

def read_batch(fname,fmt='rje'):
	if fmt == 'rje': 
		return read_rje(fname)
	if fmt == 'dos-pcc':
		return read_dos_pcc(fname)

for file in glob.glob('in\\*'):
	with open('out/' + ntpath.basename(file), 'wb') as f:
		delim = b''
		for msg in read_batch(file):
			f.write(delim)
			f.write(proc_message(msg))
			delim = b'$'
