import sys, os, socket, struct

NET_PANDA = 31


class KPLink:
    def __init__(self):
        self.sk = None
        self.recvbuf = b''
        self.pid = os.getpid()
        self._init_sk()

    def _init_sk(self):
        self.sk = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NET_PANDA)
        if not self.sk:
            print ("Error while creating netlink socket.")
            sys.exit(0)

        self.sk.bind((0, 0))

    def send(self, msg):
        sbytes = self.sk.sendto(struct.pack("<IHHII", len(msg), 0, 0, 0, self.pid) + msg, (0, 0))
        if sbytes < ((4 * 3) + (2 * 2) + len(msg)):
            print ("Netlink message wasn't sent correctly.")

    def recv(self, nb = 4096):
        return self.nlmsg_data(self.sk.recvfrom(nb)[0])

    def close(self):
        self.sk.close()

    def nlmsg_data(self, b):
        return b[16:]

link = KPLink()
link.send(b"Kppy here :)")
print (link.recv().decode('ISO-8859-1'))
link.close()
