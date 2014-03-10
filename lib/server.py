import json
import os
import logging
from sock_server import SockServer

logger = logging.getLogger('nisprac')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
fm = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(fm)
logger.addHandler(ch)

def load_config():
    """ Load config object from server configuration file """
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'server.cfg')

    with open(path) as f:
        return json.loads(f.read())

def main():
    """ Main method. Called at bottom of file. """
    cfg = load_config()

    logger.debug("Starting server with config : %s" % str(cfg))

    svr = SockServer(cfg['listenPort'])
    svr.start()

if __name__ == '__main__':
    main()