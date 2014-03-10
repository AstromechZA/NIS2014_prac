import socket
import json
import os
import base64
from key_things import load_key_from_file
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

    def encrypt_message(self, key, message):
        return base64.b64encode(key.encrypt(message, 1)[0])

    def upload_to_server(self, id, details):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.cfg['server'], self.cfg['port']))

        client_id = self.cfg['id']
        signed = self.sign_message(client_id)
        ciphertext = self.encrypt_message(self.server_key, details)

        s.send("%s|%s|%s" % (client_id, signed, ciphertext))


if __name__ == '__main__':
    c = Client()
    c.upload_to_server(7, 'Some random details, stuff stuff')