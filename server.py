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
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((options.ip,options.port))
server_socket.listen(5)

print "TCPServer Waiting for client on",options.ip,"at port",options.port

while 1:
	client_socket, address = server_socket.accept()		#Accepting connections
	print "\nGot a new connection from ", address
	
	#Stage 1
	login_data = client_socket.recv(512)
	user = login_data.split()
	Isusr = 0
	words = []
	data = 'INVALID LOGIN'
	f = open('usr_hash.txt', 'r')						#File containing login hashes
	while(1):
		line = f.readline()
		if(line == ''):
			client_socket.send(data)
			client_socket.close()
			break
		words = line.split()
		if (user[0] == words[1]):						#Matching the username for now
			Isusr = 1
			print "Login attempt by " + words[0]
			f.close()
			break
	
	if(Isusr == 0):										#If username is also not present
		client_socket.send(data)
		client_socket.close()
		continue
		
	#Selecting parameters of Diffie-Hellman
	g = int(user[2])
	b = random.randrange(1,p)
	key_b = pow(g,b,p)
	
	#Stage 2
	Ra = random.getrandbits(20)
	data=enc(str(key_b)+" "+str(Ra),words[2])
	print "Key selected: b:" + str(b) +" , key_b:" + str(key_b) + " , Ra:" + str(Ra)
	print "Ra generated :" + str(Ra)
	print "Sending Data at step 2: " + data
	client_socket.send(data)
	
	key_a = dec(user[1],words[2])
	try:
		key = pow(int(key_a),b,p)
	except Exception:
		print "INVALID LOGIN"
		client_socket.close()
		continue
	print "Final key: " + str(key)
	
	#Stage 3
	key_hash = hashlib.md5()
	key_hash.update(str(key))
	data = dec(client_socket.recv(1024),key_hash.hexdigest())
	recvd = data.split()
	
	print "Ra recovered: " + recvd[0] + "  Rb received: " + recvd[1]
	if(int(recvd[0]) != Ra):
		temp = 'Trying to hack! Authentication Failed!'
		client_socket.send(temp)
		client_socket.close()
		continue

	#Stage 4		
	data = enc(recvd[1],key_hash.hexdigest())
	print "Sending Data at step 4: " + data
	client_socket.send(data)
	
	data = client_socket.recv(2)
	if(int(data) == 1):
		print "Authentication and session key establishment complete\n"
	else:
		print "Authentication error\n"
		client_socket.close()
		continue

	os.chdir('./files')					#Changing directory
	while(1):
		data = client_socket.recv(1024)				#Encrpyted command	
		print "Command received: " + data + '\n'
		raw_inp = dec(data,key_hash.hexdigest())
		inp = raw_inp.split(None,1)
		if(inp[0] == 'q' or inp[0] == 'Q'):			#Client is quitting
			break
		elif(inp[0] == 'list'):						#Client requesting list
			filelist = os.listdir('.')
			files = "\n"
			data = enc(files.join(filelist),key_hash.hexdigest())	#Encrypting the file list
			client_socket.send(data)
			print "File list sent"
			continue
		elif(inp[0] == 'dwn'):							#Download the file
			if(inp[1] != ''):
				filename = inp[1]
				try:									#Check if file exist
					fd = open(filename,'rb')
				except IOError:
					data = enc("1",key_hash.hexdigest())
					client_socket.send(data)
					continue
				filesize = os.path.getsize(filename)
				data = enc(filename + " " + str(filesize),key_hash.hexdigest())
				client_socket.send(data)
				data = enc(fd.read(4096),key_hash.hexdigest())	#Encrypting the file
				client_socket.send(data)
				fd.close()
				print "File Sent:" + filename
			else:
				print "File not present"
			continue
			
	os.chdir('..')		
	print "Good Bye"
	client_socket.close()
