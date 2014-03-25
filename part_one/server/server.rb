require 'openssl'
require 'socket'
require 'yaml'
require 'json'
require 'base64'

class Server

  def initialize(keyring_dir, data_dir)
    @keyring_dir = keyring_dir
    @data_dir = data_dir
    @key = load_key 'self.pem'
  end

  def key_exists?(file)
    File.exists?(File.join(@keyring_dir, file))
  end

  def load_key(file)
    OpenSSL::PKey::RSA.new(File.read(File.join(@keyring_dir, file)))
  end

  def start(port)
    server = TCPServer.open(port)
    loop {
      Thread.start(server.accept) do |socket|
        begin
          client = receive_handshake(socket)
          n, sessionkey, iv = send_affirmation(socket, client)
          receive_confirmation_and_command(socket, client, n, sessionkey, iv)

          socket.close
        rescue
          puts $!.inspect, $@
        end
      end
    }
  end

  def receive_handshake(socket)
    data = JSON.load(socket.gets)
    payload = JSON.load(@key.private_decrypt(Base64.decode64(data['payload'])))
    client = {id: payload['id'], nonce: payload['nonce'], key: load_key("#{payload['id']}.pem")}
    valid = OpenSSL::Digest::SHA1.digest(JSON.dump(payload)) == client[:key].public_decrypt(Base64.decode64(data['signature']))
    raise 'signature error' if not valid

    return client
  end

  def send_affirmation(socket, client)
    n = Random.rand(2**31)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt
    k = cipher.random_key
    iv = cipher.random_iv
    payload = JSON.dump({cnonce: client[:nonce]+1, nonce: n, sessionkey: Base64.strict_encode64(k), iv: Base64.strict_encode64(iv)})
    secure_payload = Base64.strict_encode64(client[:key].public_encrypt(payload))
    signature = Base64.strict_encode64(@key.private_encrypt(OpenSSL::Digest::SHA1.digest(payload)))
    socket.puts(JSON.dump({payload: secure_payload, signature: signature}))

    return n, k, iv
  end

  def receive_confirmation_and_command(socket, client, nonce, key, iv)
    data = JSON.load(socket.gets)
    payload = JSON.load(@key.private_decrypt(Base64.decode64(data['payload'])))
    valid = OpenSSL::Digest::SHA1.digest(JSON.dump(payload)) == client[:key].public_decrypt(Base64.decode64(data['signature']))
    raise 'signature error' if not valid

    valid = (nonce + 1) == payload['snonce']
    raise 'nonce error' if not valid

    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv

    command = cipher.update(Base64.decode64(data['command'])) + cipher.final
    command = JSON.load(command)

    response = perform(command)
    response = JSON.dump(response)

    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    secure_response = Base64.strict_encode64(cipher.update(response) + cipher.final)

    socket.puts(secure_response)
  end

  def set(id, details)
    f = File.join(@data_dir, id)

    return {response: 0, message: "stored"}
  end

  def get(id)
    # check if file exists
    f = File.join(@data_dir, id)
    if File.exists?(f)

    end
    return {response: 1, message: "unknown id #{id}"}
  end

  def verify(id)
    f = File.join(@data_dir, id)
    if File.exists?(f)

    end
    return {response: 1, message: "unknown id #{id}"}
  end

  def perform(cmd)
    if cmd.include? 'action'
      case cmd['action']
      when 'set'
        return set(cmd['id'], cmd['details'])
      when 'get'
        return get(cmd['id'])
      when 'verify'
        return verify(cmd['id'])
      else
        return {response: 1, message: "unknown action #{cmd['action']}"}
      end
    else
      return {response: 1, message: 'no action supplied'}
    end
  end

end

current_dir = File.dirname(__FILE__)

cnf = YAML::load_file(File.join(current_dir, 'server.yml'))

keyring_dir = File.join(current_dir, 'keyring')
data_dir = File.join(current_dir, 'data')

s = Server.new(keyring_dir, data_dir)
s.start(cnf['listenPort'])
