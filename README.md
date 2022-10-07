->Updated: 2022 October

Tanay Mehra
(Please do not use and/or distribute this code without permission!. Thank you!)

AUTHENTICATION SERVER

This is a prototype for a network service that provides password authentication.
It is designed to be relisient against Denial-of-Service and Password Guessing attacks.

Specifics:

The service runs on TCP port #1300.
This service implements a simple protocol using Google's Protobuf (v3) Messages.
Each message is preceded by a 2 byte integer specifying the length of the following message.
The messages are of the following types:

Requests {
	Expression(username, password, expression)
	Stop()
	Reset()
}

Response {
	Expression(authenticated, result)
	Stop()
	Reset()
}

Notes:
1. An expression request is when a client sends its user crednetials to the server, along with an expression to be computed. 
The server typically stores usernames and password hashes (using PHC string formatting) and checks for correctness of said credentials 
before evaluating the expression and returning the result.
	1a. The server stores user credentials in a TOML document, as an array of <username, password_hash> key-value pairs.
	1b. The server supports the following hashing algorithms:
		1. SHA-256
		2. SHA-512
		3. bcrypt
		4. Argon2
	1c. Incorrect password credentials earn the offending client IP a 'strike' in the hitlist. 3 Strikes and the client IP goes into the actively maintained blocklist.
	1d. The server will spend at most 5 seconds in attempting to evaluate the sent expression. If the expression si not evaluated aand returned within that 5 second window then the client IP is perma-blocked.

2. A Stop request will terminate the connection and stow the server.

3. A ResetBlockList request will expunge all entries in the blocklist.

4. responses to the requests are created, serialized and sent by the server. A failed authentication or expression evaluation will merit a null result from the server.

Building and running:
In order to build and run this server locally, please do the following:
	1. Clone this repo.
	2. Make sure you have docker installed.
	3. CD to this directory and Run: docker build -t authd -f Dockerfile .
	4. Once you have the image, run: docker run -it --rm -p 1300:1300 -v ./src/users.toml:/tmp/users.toml authd /tmp/users.toml
	5. To stop, run: docker stop authd


 
