import json
import os

def load_config():
    ''' Load config object from server configuration file '''
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                        '..', 'server.cfg')

    with open(path) as f:
        return json.loads(f.read())

def main():
    ''' Main method. Called at bottom of file. '''
    cfg = load_config()
    print cfg

if __name__ == '__main__':
    main()