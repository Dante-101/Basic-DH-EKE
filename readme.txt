CS 416 - Computer and Network Security
Programming Assignment 2
-----------------------------------------------------------
Made by : 	Gaurav Lahoti
Date : 		4th April 2011
Made on : 	Dell Studio XPS, i7 720qm, 6GB DDR3, ATI Mobility Radeon 5730; Ubuntu 10.10 x64; Python 2.6.6;
Libraries Used : socket, random, sys, base64 (for base64 encoding the data before the encryption), hashlib (for calculatin md5 hash), os (for file utilities), Crypto.Cipher (for AES), optparse
-----------------------------------------------------------

Summary:
This project is mainly focused on network security and authentication. It implements the EKE (Encrypted Key Exchange) Protocol which has been explained below. For encrypting the data, I have used AES-128 bit encryption with block and key sizes of 128 bit. For key sizes of 128 bit, I have used the md5 hashes of the values which needed to act as the key. For authentication, md5 hash of password and for session key, Diffie-Hellman key exchange method has been used. Finally, after the server and the client authenticates and a session key is agreed upon, the server acts like a file server. The client can query the files present on the server and then download the file he wishes. All the commands isued by the client as well as the file data is encrypted before sending on network and decrypted in receiving. For the purpose of just demonstration, the file size that can be transferred has been limited to 4KB.

Files and folders present:
-->client.py
			This file contains the client side program.
-->server.py
			This file contains the server side program.
-->Readme.txt
			The help file which you are reading right now.
-->Users.txt
			This file contains the username and the passwords of the users that can connect to the server. This is has been kept to add more users or change the password.
-->usr_hash.txt
			This file contains the md5 hashes of the username and the passwords of the users. Only this file is opened by the server.
-->hash.py
			This file takes Users.txt, converts the username and passwords into md5 hashes and stores the hashes into usr_hash.txt
-->files
			This folder is contains some sample files. The server lists the content of this folder only.
-->files_dwn
			This is the folder where the client downloads the file.

EKE Protocol:
The EKE protocol implemented in this is as follows:

	A(Client)				B (Server)
	|						|
	| 'A', Epw((g^a) mod p) |	(Stage 1)
	|---------------------->|
	|						|
	| Epw((g^b) mod p, Ra)  |	(Stage 2)
	|<----------------------|
	|						|
	| 	   Ek(Ra, Rb) 		|	(Stage 3)
	|---------------------->|
	|						|
	|		Ek(Rb)			|	(Stage 4)
	|<----------------------|


Epw() and Ek() represent the encrption (AES-128 bit) using md5 hashes of password and the session key (k = g^(ab) mod p) as the keys.

Some important points:

1) For demonstration purpose, in diffie-hellman, a constant value of p = 13 has been taken and one the 4 generators of 13 (2,6,7,11) is chosen randomly for each session.
2) The library Crypto.Cipher has been used for AES 128 bit encryption. Sometimes, those libraries might not be present in the python installation.
3) If no parameters for ip adress and port is provided, the server and the client program take the default as 127.0.0.1 and 5001 respectively

USAGE:
Make the program folder as the current directory.

For making changes to users, change the 'Users.txt' with the requires username and password. Run 'python hash.py' to update 'usr_hash.txt'

-->server.py
		To run the server, type 'python server.py'. A server will start at loopback ip 127.0.0.1, port 5001.
		To specify some other parameters, use the following options:
		-i 		specify the ip address
		-p 		port number
		
		For example: $ python server.py -i 10.8.234.235 -p 12300

-->client.py
		To run this type 'python client.py'. You need to specify username and password for the program to work.
		The supported parameters are as follows:
		-i 		specify the ip address (default 127.0.0.1)
		-p 		port number	(default 5001)
		-u 		username
		-q 		password
		
		For example: $ python client.py -i 10.8.234.235 -p 12300 -u gaurav -q asap
		
After running the files, the client will connect to the server and they both will authenticate themselves via EKE protocol. The output of each stage of protocol is shown on the terminal of the sender machine. If authentication and session key is done successfully, then a message for the same is printed. Then the client side waits for the command for the server.

Following three commands are supported for the file server:
1) list - This will list all the files in the folder.
2) dwn - This command is for downloading the life. It needs to be followed by the name of the file to be downloaded. If no name/wrong name is provided, program just flags an error.
3) q - This command is to quit the client side program. On pressing this, the connection will be closed and the client program is finished. But the server still continues.
