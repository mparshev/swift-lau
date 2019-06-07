#
# LAU key calculation/verification for SWIFT
#

import glob
import hmac
import hashlib
import sys
import re
import ntpath

LAU_KEY = b'Abcdef1234567890Abcdef1234567890'

# extract {S: block from message
def split_message(msg):
	m = re.search(r'{S:.*}', msg)
	if m:
		s = m.group(0)
		return msg.replace(s, ''), s 
	else:
		return msg, ''

# find digest {MDG:
def find_digest(msg):
	m = re.search(r'{MDG:(\w+)}', msg)
	if m: return m.group(1)

# calc digest value
def sign(msg):
	dig = hmac.new(LAU_KEY, msg=msg, digestmod=hashlib.sha256).digest()
	return dig.hex().upper()

# proceed message 		
def proc_message(msg):
	msg, s = split_message(msg)
	dig = sign(msg.encode())
	if s:
		d = find_digest(s)
		if d:
			if d != dig : 
				print('Warning! Incorrect digest.')
			else:
				print('Digest ok.')
			msg += s.replace(d, dig)
		else:
			msg += '{' + s[1:-1] + '{MDG:' + dig + '}}'
	else:
		msg += '{S:{MDG:' + dig + '}}'
	return msg.encode()

# read any batch (dos-pcc or rje)
def read_any_batch(fname):
	msg=b''
	fmt=''
	with open(fname,'rb') as fi:
		while True:
			ch = fi.read(1)
			if ch==b'\x01':
				msg=b''
				if fmt=='': fmt='pcc'
			elif fmt=='pcc' and ch==b'\x03':
				yield msg.decode()
				#proc_message(msg.decode())
			elif fmt=='rje' and (not ch or ch==b'$'):
				yield msg.decode()
				msg=b''
			else:
				msg += ch
				if fmt=='': fmt='rje'
			if not ch: break


for file in glob.glob('in\\*'):
	with open('out/' + ntpath.basename(file), 'wb') as f:
		delim = b''
		for msg in read_any_batch(file):
			f.write(delim)
			f.write(proc_message(msg))
			delim = b'$'

