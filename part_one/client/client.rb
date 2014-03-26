require 'openssl'
require 'socket'
require 'yaml'
require 'json'
require 'base64'
require 'logger'

$log = Logger.new(STDOUT)
$log.level = Logger::INFO
$log.formatter = proc do |severity, datetime, progname, msg|
   "[#{datetime.strftime('%F %T')} #{severity}] #{msg}\n"
end

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
    $log.info "Connecting to #{remote}:#{port}"
    s = TCPSocket.new(remote, port)

    $log.debug 'Sending handshake'
    n = send_handshake(s)

    $log.debug 'Waiting for affirmation'
    sn, k, iv = receive_affirmation(s, n)

    $log.debug 'Sending confirmation and command'
    send_confirmation_and_command(s, sn, k, iv, {id: id, details: details})

    $log.debug 'Waiting for response'
    receiver_response(s, k, iv)

    s.close

    $log.debug 'Closing socket'
    $log.info 'Done'
  end

  def makeRSApayload(hash, selfkey, otherkey)
    payload = JSON.dump(hash)
    secure_payload = Base64.strict_encode64(otherkey.public_encrypt(payload))
    signature = Base64.strict_encode64(selfkey.private_encrypt(OpenSSL::Digest::SHA1.digest(payload)))
    return {payload: secure_payload, signature: signature}
  end

  def checkRSApayloadSignature(data, selfkey, otherkey)
    payload = JSON.load(selfkey.private_decrypt(Base64.decode64(data['payload'])))
    valid = OpenSSL::Digest::SHA1.digest(JSON.dump(payload)) == otherkey.public_decrypt(Base64.decode64(data['signature']))
    raise 'signature error' if not valid
    return payload
  end

  def send_handshake(socket)
    n = Random.rand(2**31)

    payload = makeRSApayload({id: @id, nonce: n}, @key, @server_key)
    socket.puts(JSON.dump(payload))

    return n
  end

  def receive_affirmation(socket, nonce)
    data = JSON.load(socket.gets)

    payload = checkRSApayloadSignature(data, @key, @server_key)

    valid = (nonce + 1) == payload['cnonce']
    raise 'nonce error' if not valid

    $log.info('Server is now trusted. (auth + fresh)')
    return payload['nonce'], Base64.decode64(payload['sessionkey']), Base64.decode64(payload['iv'])
  end

  def send_confirmation_and_command(socket, snonce, sessionkey, iv, command)
    n = Random.rand(2**31)

    payload = makeRSApayload({snonce: snonce+1, cnonce: n}, @key, @server_key)

    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt
    cipher.key = sessionkey
    cipher.iv = iv

    command = JSON.dump(command)

    secure_command = Base64.strict_encode64(cipher.update(command) + cipher.final)

    payload[:command] = secure_command

    socket.puts(JSON.dump(payload))
  end


  def receiver_response(socket, key, iv)
    data = Base64.decode64(socket.gets)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    r = JSON.load(cipher.update(data) + cipher.final)

    if r['response'] == 0
      $log.info r
    else
      $log.error "Server error '#{r['message']}'"
    end


  end

end

current_dir = File.dirname(__FILE__)

cnf = YAML::load_file(File.join(current_dir, 'client.yml'))
$log.info "Starting client with #{cnf}"
$log.level = Logger.const_get(cnf['log_level']) if cnf.has_key? 'log_level'

c = Client.new(cnf['id'], File.join(current_dir, 'keyring'))
c.upload('007', 'Some details', cnf['server'], cnf['port'])




