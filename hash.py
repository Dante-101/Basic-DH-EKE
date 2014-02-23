#!/usr/bin/env python

import hashlib

f = open('Users.txt', 'r')
fh = open('usr_hash.txt', 'w')
lines = f.readlines()
h=len(lines);

i=0
for i in range(h):	
	words=lines[i].split()
	usr = hashlib.md5()
	usr.update(words[0])
	pwd = hashlib.md5()
	pwd.update(words[1])
	fh.write(words[0] + ' ' + usr.hexdigest() + ' ' + pwd.hexdigest() + '\n')
	
f.close()
fh.close()
