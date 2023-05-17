"""
Code resourced from https://pythonprogramming.net/server-chatroom-sockets-tutorial-python-3/
for the chat server and client.

Code resourced from https://www.delftstack.com/howto/python/python-aes-encryption/
for encryption AES code.

"""


import socket
import select
import errno
import sys
#AES MODULES FOR ENCRYPTION
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import time
#import keyboard

BLOCK_SIZE = 16
pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]
key = '1234'

"""
Function: encrypt
args: (str) plain_text - text to be encrypted
      (int) key - encryption key 
encry
This function encrypts a message using AES.
"""

def encrypt(plain_text, key):
    private_key = hashlib.sha256(bytes(key.encode("utf-8"))).digest()
    plain_text = pad(plain_text)
    #print("After padding:", plain_text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plain_text))

"""
Function: decrypt
args: (str) cipher_text - the encrypted text
      (int) key - decryption key 

This function decrypts a message using AES.
"""
def decrypt(cipher_text, key):
    private_key = hashlib.sha256(bytes(key.encode("utf-8"))).digest()
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[16:]))


HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 8080
my_username = input("Username: ")

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
client_socket.connect((IP, PORT))

# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

#client_socket.listen(5)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

while True:
    #time.sleep(5)
    #keyboard.press_and_release('enter')
    # Wait for user to input a message
    message = input(f'{my_username} > ')

    # If message is not empty - send it
    if message:

        # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
        #message = message.encode('utf-8')
        message = encrypt(message, key)
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + message)
        
    else:

        try:

            # Now we want to loop over received messages (there might be more than one) and p
            # rint them
            while True:

                # Receive our "header" containing username length, it's size is defined and constant
                username_header = client_socket.recv(HEADER_LENGTH)

                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not len(username_header):
                    print('Connection closed by the server')
                    sys.exit()

                # Convert header to int value
                username_length = int(username_header.decode('utf-8').strip())

                # Receive and decode username
                username = client_socket.recv(username_length).decode('utf-8')

                # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode('utf-8').strip())
                message = (decrypt(client_socket.recv(message_length).decode('utf-8'), key))

                # Print message
                print(f'{username} > {message.decode()}')

        except IOError as e:
            # This is normal on non blocking connections - when there are no incoming data error is going to be raised
            # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
            # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
            # If we got different error code - something happened
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()

            # We just did not receive anything
            continue

        except Exception as e:
            # Any other exception - something happened, exit
            print('Reading error: '.format(str(e)))
            sys.exit()
