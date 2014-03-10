import socket
import logging

logger = logging.getLogger('nisprac.socksvr')

class SockServer(object):
    """ A Server for the listen server """

    def __init__(self, port):
        super(SockServer, self).__init__()
        self.port = port
        self.__bind_socket()
        self.__listen()

    def start(self):
        self.__listen()

    def __bind_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('', self.port))

    def __listen(self):
        self.socket.listen(1)
        (conn, addr) = self.socket.accept()
        logger.info("Got connection from %s:%i" % (addr[0], addr[1]))




