import logging
import base64
import socket
import json
import sys
from Crypto.Random import random
from Crypto import Random

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP

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

    def encrypt_message(self, key, message):
        k = PKCS1_OAEP.new(key)
        return base64.b64encode(k.encrypt(str(message)))

    def decrypt_message(self, key, message):
        k = PKCS1_OAEP.new(key)
        return k.decrypt(base64.b64decode(message))

    def verify_message(self, message, signed_text, sender_key):
        return PKCS1_v1_5.new(sender_key).verify(SHA.new(message), base64.b64decode(signed_text))

    def make_nonce(self):
        return random.getrandbits(31)


    def wait_for_identify(self):
        data = self.conn.recv(4096)
        logger.debug("Received message of %i bytes" % len(data))

        # json to obj
        r = json.loads(data)
        # decrypt payload
        payload = json.loads(self.decrypt_message(self.my_key, r['payload']))
        # get client info
        c_id = payload['id']
        c_nonce = int(payload['nonce'])
        # load correct key
        c_key = load_key_from_file("keyring/%s.pub" % c_id)
        # verify integrity
        check = self.verify_message(r['payload'], r['signature'], c_key)

        if not check:
            raise Exception("Signature does not match payload apparently from client %s" % c_id)

        logger.debug("Signature matches payload. Was signed by clients private key")

        c = {}
        c['id'] = c_id
        c['key'] = c_key
        c['nonce'] = c_nonce
        return c

    def send_handshake(self, client):
        # create nonce
        nonce = self.make_nonce()
        # increment client nonce
        c_nonce = client['nonce'] + 1
        # create secret key
        s_key = base64.b64encode(Random.new().read(32))
        # construct payload
        payload = json.dumps({'nonce': nonce, 'c_nonce': c_nonce, 's_key': s_key})
        # encrypt payload
        securepayload = self.encrypt_message(client['key'], payload)
        # signature
        signature = self.sign_message(securepayload)
        # final
        request = json.dumps({'payload': securepayload, 'signature': signature})
        # send
        self.conn.send(request)



    def process(self):
        logger.info('Processing')
        try:
            client = self.wait_for_identify()
            self.send_handshake(client)
        except Exception, e:
            logger.exception(e)
        finally:
            logger.info('Closing connection')
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()

