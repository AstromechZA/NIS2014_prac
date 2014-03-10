import logging
import base64

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

from key_things import load_key_from_file

logger = logging.getLogger('nisprac.connhandler')

class ConnectionHandler(object):
    """   """

    def __init__(self, conn, cfg):
        super(ConnectionHandler, self).__init__()
        self.conn = conn
        self.cfg = cfg
        self.my_key = load_key_from_file('keyring/self.pem')

    def process(self):
        logger.info('Processing')
        data = self.conn.recv(4096)
        parts = data.split('|')
        cid = parts[0]
        c_key = load_key_from_file("keyring/%s.pub" % cid)
        c_signer = PKCS1_v1_5.new(c_key)
        r = base64.b64decode(parts[1])
        print c_signer.verify(SHA.new(cid), r)