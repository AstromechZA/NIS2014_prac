import logging

logger = logging.getLogger('nisprac.connhandler')

class ConnectionHandler(object):
    """   """

    def __init__(self, conn, cfg):
        super(ConnectionHandler, self).__init__()
        self.conn = conn
        self.cfg = cfg

    def process(self):
        logger.info('Processing')
