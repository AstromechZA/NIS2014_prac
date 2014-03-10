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
        self.signer = PKCS1_v1_5.new(self.my_key)

    def sign_message(self, message):
        return base64.b64encode(self.signer.sign(SHA.new(message)))

    def verify_message(self, message, signed_text, sender_key):
        return PKCS1_v1_5.new(sender_key).verify(SHA.new(message), base64.b64decode(signed_text))

    def process(self):
        logger.info('Processing')
        data = self.conn.recv(4096)
        parts = data.split('|')
        cid = parts[0]
        c_key = load_key_from_file("keyring/%s.pub" % cid)
        print self.verify_message(cid, parts[1], c_key)
        print self.my_key.decrypt(base64.b64decode(parts[2]))
