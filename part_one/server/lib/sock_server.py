import socket
import logging
import thread

from connection_handler import ConnectionHandler

logger = logging.getLogger('nisprac.socksvr')

class SockServer(object):
    """ A Server for the listen server """

    def __init__(self, port, cfg):
        super(SockServer, self).__init__()
        self.port = port
        self.socket = self.__bind_socket()
        self.cfg = cfg

    def start(self):
        self.__listen()
        try:
            while True:
                self.__accept()
        except KeyboardInterrupt:
            print 'Shutting down.'
        self.socket.shutdown(socket.SHUT_RDWR)
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

        ch = ConnectionHandler(conn, self.cfg)
        thread.start_new_thread(ch.process, ())
