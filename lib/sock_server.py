import socket
import logging

logger = logging.getLogger('nisprac.socksvr')

class SockServer(object):
    """ A Server for the listen server """

    def __init__(self, port):
        super(SockServer, self).__init__()
        self.port = port
        self.socket = self.__bind_socket()

    def start(self):
        self.__listen()
        while True:
            self.__accept()
        self.socket.close()

    def __bind_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', self.port))
        return s

    def __listen(self):
        self.socket.listen(4)
        logger.info("Listening on port %s" % self.port)

    def __accept(self):
        (conn, addr) = self.socket.accept()
        logger.info("Got connection from %s:%i" % (addr[0], addr[1]))
        # todo
        logger.info("Finished")




