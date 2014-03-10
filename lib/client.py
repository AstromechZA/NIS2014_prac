import socket
import json
import os

def load_config():
    """ Load config object from client configuration file """
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                        '..', 'client.cfg')
    with open(path) as f:
        return json.loads(f.read())

cfg = load_config()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((cfg['server'], cfg['port']))
s.send('hello')