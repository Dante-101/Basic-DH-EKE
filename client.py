#!/usr/bin/env python

import hashlib								#For md5 sum
import socket					
import random								#For generating the nonce
import base64								#base 64 encoding of data before encryption
import os
import sys
from Crypto.Cipher import AES				#AES library
from optparse import OptionParser
parser = OptionParser()
# Command Line for message
parser.add_option("-i", "--server_IP", 
                  dest="ip", type="str", default="127.0.0.1",
                  help = "Input Server IP")

parser.add_option("-p", "--port", 
                  dest="port", type="int", default="5001",
                  help = "Input Server Port")

parser.add_option("-u", "--username", 
                  dest="uname",type="str", default="",
                  help = "Username")

parser.add_option("-q", "--password", 
                  dest="passwd",type="str", default="",
                  help = "Password")

(options, args) = parser.parse_args()

p = 13								#Diffie-Hellman constant p
GEN = [2,6,11,7]					#Generators of p
BLOCK_SIZE = 16						#Block size
xtra = ' '							#Add extra space at the end to make the input size a multiple of block size
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * xtra

def enc(msg,key):					#Encrypting AES
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	cipher = AES.new(key)
	encoded = EncodeAES(cipher, msg)
	#print '\nEncrypted string: ', encoded
	return encoded
	
def dec(msg,key):					#Decrypting AES
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(xtra)
	cipher = AES.new(key)
	decoded = DecodeAES(cipher, msg)
	#print '\nDecrypted string: ', decoded
	return decoded

#Making connections
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((options.ip,options.port))

#Generating Hashes
usr = hashlib.md5()
usr.update(options.uname)
pwd = hashlib.md5()
pwd.update(options.passwd)

#Selecting parameters of Diffie-Hellman
g =	GEN[random.randrange(0,4)]
a = random.randrange(1,p)
key_a = pow(g,a,p)

#Stage 1
data=usr.hexdigest()+" "+enc(str(key_a),pwd.hexdigest())+" "+str(g)
print "Key selected: g:" + str(g) + " , a:" + str(a) + " , p:" + str(p) + " , key_a:" + str(key_a)
print "Sending Data at step 1: " + data
client_socket.send(data)

#Stage 2
data = dec(client_socket.recv(1024),pwd.hexdigest())
recvd = data.split()
try:
	key = pow(int(recvd[0]),a,p)
except Exception:
	print "INVALID LOGIN"
	client_socket.close()
	sys.exit()
print "Final key: " + str(key)

#Stage 3
Rb = random.getrandbits(20)
print "Ra received :" + str(recvd[1]) + "  Rb generated:" + str(Rb)
key_hash = hashlib.md5()
key_hash.update(str(key))
data = enc(recvd[1] + " " + str(Rb),key_hash.hexdigest())
print "Sending Data at step 3: " + data
client_socket.send(data)

#Stage 4
data = client_socket.recv(1024)
data = dec(data,key_hash.hexdigest())
recvd = data.split()

print "Rb recovered: " + str(recvd[0])

if(int(recvd[0]) != Rb):
	data ='Trying to hack! Authentication Failed'
	client_socket.send(data)
	client_socket.close()
	sys.exit()
	
data = '1'
client_socket.send(data)
print "Authentication and session key establishment complete"

#File Server
inp = ''
print "\nPRESS Q TO EXIT"

os.chdir('./files_dwn')

while(1):
	raw_inp = raw_input("Enter the command: ")
	inp = raw_inp.split(None,1)
	if(inp[0] == 'q' or inp[0] == 'Q'):				#To quit
		data = enc(inp[0],key_hash.hexdigest())
		client_socket.send(data)
		break
	elif(inp[0] == 'list'):							# To list the files
		data = enc(inp[0],key_hash.hexdigest())		#Encrypting and sending the command
		client_socket.send(data)
		data =	client_socket.recv(4096)			#Receiving encrytped file list
		print "File list received: " + data + '\n'
		files = dec(data,key_hash.hexdigest())		#Decrypting file list
		print files
		continue
	elif(inp[0] == 'dwn'):							#To download the file
		if(inp[1] != ''):
			data = enc(raw_inp,key_hash.hexdigest())					#Encrypting and sending the command
			client_socket.send(data)
			files = dec(client_socket.recv(4096),key_hash.hexdigest())	#Decrypting the file parameters
			files = files.split()
			if(len(files) == 1):
				print "File not present"
				continue
			filename = files[0]
			filesize = long(files[1])
			f = open(filename,'wb')
			f.write(dec(client_socket.recv(4096),key_hash.hexdigest()))	#Decrypting the file
			f.close()
			if(filesize < 4096):
				print "File downloaded"
			else:
				print "Only the starting 4KB of File has been downloaded"
		else:
			print "File not present"
		continue			
			
			
print "Good Bye"
client_socket.close()
