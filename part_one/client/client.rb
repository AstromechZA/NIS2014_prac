require 'openssl'
require 'socket'
require 'yaml'
require 'json'
require 'base64'

class Client
    def initialize(id, keyring)
        @id = id
        @keyring = keyring
        @key = load_key 'self.pem'
    end

    def load_key(file)
        OpenSSL::PKey::RSA.new File.read File.join @keyring, file
    end

    def upload(id, details, remote, port)
        s = TCPSocket.new remote, port

        n = start_handshake s

        s.close
    end

    def start_handshake(socket)
        n = Random.rand 2**31

        payload = JSON.dump {id: @id, nonce: n}

        secure_payload = Base64.encode64 @key.private_encrypt payload

        signature = Base64.encode64 @key.private_encrypt OpenSSL::Digest::SHA1.digest payload

        r = JSON.dump {payload: secure_payload, signature: signature}

        socket.puts r

        return n
    end

end

current_dir = File.dirname __FILE__

cnf = YAML::load_file File.join current_dir, 'client.yml'
puts cnf

c = Client.new cnf['id'], File.join(current_dir, 'keyring')
c.upload '007', 'Some details', cnf['server'], cnf['port']




