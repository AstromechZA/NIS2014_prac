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
    @server_key = load_key 'server.pem'
  end

  def load_key(file)
    OpenSSL::PKey::RSA.new(File.read(File.join(@keyring, file)))
  end

  def upload(id, details, remote, port)
    s = TCPSocket.new(remote, port)
    n = send_handshake(s)
    sn, k, iv = receive_affirmation(s, n)
    send_confirmation_and_command(s, sn, k, iv, id, details)
    receiver_response(s, k, iv)
    s.close
  end

  def send_handshake(socket)
    n = Random.rand(2**31)
    payload = JSON.dump({id: @id, nonce: n})
    secure_payload = Base64.encode64(@server_key.public_encrypt(payload))
    signature = Base64.encode64(@key.private_encrypt(OpenSSL::Digest::SHA1.digest(payload)))
    socket.puts(JSON.dump({payload: secure_payload, signature: signature}))

    return n
  end

  def receive_affirmation(socket, nonce)
    data = JSON.load(socket.gets)
    payload = JSON.load(@key.private_decrypt(Base64.decode64(data['payload'])))
    valid = OpenSSL::Digest::SHA1.digest(JSON.dump(payload)) == @server_key.public_decrypt(Base64.decode64(data['signature']))
    raise 'signature error' if not valid

    valid = (nonce + 1) == payload['cnonce']
    raise 'nonce error' if not valid

    return payload['nonce'], Base64.decode64(payload['sessionkey']), Base64.decode64(payload['iv'])
  end

  def send_confirmation_and_command(socket, nonce, sessionkey, iv, id, details)
    payload = JSON.dump({snonce: nonce+1})
    secure_payload = Base64.encode64(@server_key.public_encrypt(payload))
    signature = Base64.encode64(@key.private_encrypt(OpenSSL::Digest::SHA1.digest(payload)))

    command = JSON.dump({id: id, details: details})

    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt
    cipher.key = sessionkey
    cipher.iv = iv

    secure_command = Base64.encode64(cipher.update(command) + cipher.final)

    socket.puts(JSON.dump({payload: secure_payload, signature: signature, command: secure_command}))
  end

  def receiver_response(socket, key, iv)
    data = Base64.decode64(socket.gets)

    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv

    r = JSON.load(cipher.update(data) + cipher.final)

    puts r

  end

end

current_dir = File.dirname(__FILE__)

cnf = YAML::load_file(File.join(current_dir, 'client.yml'))
puts cnf

c = Client.new(cnf['id'], File.join(current_dir, 'keyring'))
c.upload('007', 'Some details', cnf['server'], cnf['port'])




