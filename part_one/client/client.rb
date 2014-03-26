require 'openssl'
require 'socket'
require 'yaml'
require 'json'
require 'base64'
require 'logger'
$: << File.join(File.dirname(__FILE__), '..')
require 'crypto_utils'

$log = Logger.new(STDOUT)
$log.level = Logger::INFO
$log.formatter = proc do |severity, datetime, progname, msg|
   "[#{datetime.strftime('%F %T')} #{severity}] #{msg}\n"
end

class Client
  def initialize(id, keyring)
    @id = id
    @keyring = keyring
    @key = CryptoUtils::load_key File.join(@keyring, 'self.pem')
    @server_key = CryptoUtils::load_key File.join(@keyring, 'server.pem')
  end

  def upload(id, details, remote, port)
    $log.info "Connecting to #{remote}:#{port}"
    socket = TCPSocket.new(remote, port)

    $log.debug 'Sending handshake'
    cnonce = send_handshake(socket)

    $log.debug 'Waiting for affirmation'
    snonce, key, iv = receive_affirmation(socket, cnonce)

    $log.debug 'Sending confirmation and command'
    send_confirmation_and_command(socket, snonce, key, iv, {id: id, details: details})

    $log.debug 'Waiting for response'
    receiver_response(socket, key, iv)

    socket.close

    $log.debug 'Closing socket'
    $log.info 'Done'
  end

  # handshake message
  # Identifies the client to the server
  def send_handshake(socket)
    # create nonce
    n = Random.rand(2**31)
    # construct payload with signed version
    payload = CryptoUtils::makeRSApayload({id: @id, cnonce: n}, @key, @server_key)
    # send to server
    socket.puts(JSON.dump(payload))
    # return nonce value
    return n
  end

  # affirmation message
  # Server sends back incremented client nonce, server nonce, and a master key+iv
  def receive_affirmation(socket, cnonce)
    # get message
    data = JSON.load(socket.gets)
    # verify signature
    payload = CryptoUtils::checkRSApayloadSignature(data, @key, @server_key)
    # verify nonce
    valid = (cnonce + 1) == payload['cnonce']
    raise 'nonce error' if not valid
    # state
    $log.info('Server is now trusted. (auth + fresh)')
    # return
    return payload['snonce'], Base64.decode64(payload['sessionkey']), Base64.decode64(payload['iv'])
  end

  # confirmation

  def send_confirmation_and_command(socket, snonce, key, iv, command)
    n = Random.rand(2**31)

    payload = CryptoUtils::makeRSApayload({snonce: snonce+1, cnonce: n}, @key, @server_key)

    command = JSON.dump(command)

    ciphertext = CryptoUtils::encryptAES(command, key, iv)

    secure_command = Base64.strict_encode64(ciphertext)

    payload[:command] = secure_command

    socket.puts(JSON.dump(payload))
  end


  def receiver_response(socket, key, iv)
    data = Base64.decode64(socket.gets)

    plaintext = CryptoUtils::decryptAES(data, key, iv)

    r = JSON.load(plaintext)

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




