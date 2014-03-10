import os
from Crypto.PublicKey import RSA

def load_key_from_file(path):
    """ Create key from file """
    p = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', path)
    with open(os.path.abspath(p)) as f:
        return RSA.importKey(f.read())
