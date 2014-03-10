import socket
import json
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

def load_config():
    """ Load config object from client configuration file """
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'client.cfg')
    with open(path) as f:
        return json.loads(f.read())

def load_key_from_file(path):
    """ Create key from file """
    p = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', path)
    with open(os.path.abspath(p)) as f:
        return RSA.importKey(f.read())

cfg = load_config()

server_key = load_key_from_file('keyring/server.pub')
my_key = load_key_from_file('keyring/self.pem')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((cfg['server'], cfg['port']))

client_id = cfg['id']
hash_of_id = SHA.new(client_id)
signer = PKCS1_v1_5.new(my_key)
signed = base64.b64encode(signer.sign(hash_of_id))

s.send("%s|%s" % (client_id, signed))
