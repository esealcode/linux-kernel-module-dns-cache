import socket
import sys

sv = ('127.0.0.1', 7777)
sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("Sending 128 bytes chunk UDP data...")
sk.sendto('A' * 128, sv)

print("Sending 512 bytes chunk UDP data...")
sk.sendto('B' * 512, sv)

print("Sending 1024 bytes chunk UDP data...")
sk.sendto('C' * 1024, sv)

sk.close()
sys.exit(0);
