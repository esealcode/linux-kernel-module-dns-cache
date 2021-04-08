import socket
import sys

# This mini-server aim to wait for DNS module hook redirect and read redirected data
# It just basically listen for everything in UDP on :7777

HOST = '0.0.0.0'
PORT = 7777

sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP Socket

try:
    sk.bind((HOST, PORT))
except socket.error as msg:
    print ("Bind failed.")

print ("Server is listening on :%d" % (PORT))
while 1:
    buf, addr = sk.recvfrom(4096)
    print ("Received: %s from %s:%d" % (buf, addr[0], addr[1]))
