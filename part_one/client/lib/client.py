import socket
import json
import os
import sys
import base64
from key_things import load_key_from_file
import random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

class Client(object):
    """ docstring for Client """

    def __init__(self):
        super(Client, self).__init__()
        self.cfg = self.load_config()
        self.my_key = load_key_from_file('keyring/self.pem')
        self.signer = PKCS1_v1_5.new(self.my_key)
        self.server_key = load_key_from_file('keyring/server.pub')

    def load_config(self):
        """ Load config object from client configuration file """
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'client.cfg')
        with open(path) as f:
            return json.loads(f.read())

    def sign_message(self, message):
        return base64.b64encode(self.signer.sign(SHA.new(message)))

    def verify_message(self, message, signed_text, sender_key):
        return PKCS1_v1_5.new(sender_key).verify(SHA.new(message), base64.b64decode(signed_text))

    def encrypt_message(self, key, message):
        return base64.b64encode(key.encrypt(str(message), 32)[0])

    def decrypt_message(self, key, message):
        return key.decrypt(base64.b64decode(message))

    def make_nonce(self):
        return random.randint(0, sys.maxint-1)

    def upload_to_server(self, id, details):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.cfg['server'], self.cfg['port']))

        client_id = self.cfg['id']


        # ======== message one - identify self =========
        # nonce
        nonce = self.make_nonce()
        # payload
        payload = json.dumps({'id': client_id, 'nonce': nonce})
        # encrypt payload
        securepayload = self.encrypt_message(self.server_key, payload)
        # signature
        signature = self.sign_message(securepayload)
        # final
        request = json.dumps({'payload': securepayload, 'signature': signature})
        # send
        s.send(request)


        data = s.recv(4096)
        print ("Received message of %i bytes" % len(data))
        r = json.loads(data)
        # check that signature matches payload
        check = self.verify_message(r['payload'], r['signature'], self.server_key)
        print check
        # decrypt payload
        payload = self.decrypt_message(self.my_key, r['payload'])
        print json.loads(payload)


if __name__ == '__main__':
    c = Client()
    c.upload_to_server(7, 'Some random details, stuff stuff')