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
    @sessionkey = nil
    @sessioniv = nil
    @last_cnonce = nil
    @last_snonce = nil
  end

  def authenticate(remote, port)
    $log.info "Connecting to #{remote}:#{port}"
    @socket = TCPSocket.new(remote, port)

    $log.debug 'Sending handshake'
    send_handshake(@socket)

    $log.debug 'Waiting for affirmation'
    receive_affirmation(@socket)

    $log.debug 'Sending confirmation'
    send_confirmation(@socket)

    $log.debug 'Waiting for ready'
    receive_ready(@socket)
  end

  def close
    send_command(@socket, {action: 'quit'})
    $log.debug 'Closing socket'
    @socket.close
  end


  # handshake message
  # Identifies the client to the server
  def send_handshake(socket)
    # create nonce
    @last_cnonce = Random.rand(2**31)
    # construct payload with signed version
    payload = CryptoUtils::makeRSApayload({id: @id, cnonce: @last_cnonce}, @key, @server_key)
    # send to server
    socket.puts(JSON.dump(payload))
  end

  # affirmation message
  # Server sends back incremented client nonce, server nonce, and a master key+iv
  def receive_affirmation(socket)
    # get message
    data = JSON.load(socket.gets)
    # verify signature
    payload = CryptoUtils::checkRSApayloadSignature(data, @key, @server_key)
    # verify nonce
    valid = (@last_cnonce + 1) == payload['cnonce']
    raise 'nonce error' if not valid
    # state
    $log.info('Server is now trusted. (auth + fresh)')

    @last_snonce = payload['snonce']
    @sessionkey = Base64.decode64(payload['sessionkey'])
    @sessioniv = Base64.decode64(payload['iv'])
  end

  # confirmation
  def send_confirmation(socket)
    @last_cnonce = Random.rand(2**31)

    payload = CryptoUtils::makeRSApayload({snonce: @last_snonce+1, cnonce: @last_cnonce}, @key, @server_key)

    ciphertext = CryptoUtils::encryptAES('abcdefghijklmnopqrstuvwxyz', @sessionkey, @sessioniv)

    payload[:check] = Base64.strict_encode64(ciphertext)

    socket.puts(JSON.dump(payload))
  end

  def receive_ready(socket)
    data = Base64.decode64(socket.gets)

    plaintext = CryptoUtils::decryptAES(data, @sessionkey, @sessioniv)

    payload = JSON.load(plaintext)

    valid = (@last_cnonce + 1) == payload['cnonce']
    raise 'nonce error' if not valid

    @last_snonce = payload['snonce']

    payload.delete('cnonce')
    payload.delete('snonce')

    return payload
  end

  def send_command(socket, command)
    @last_cnonce = Random.rand(2**31)

    payload = CryptoUtils::makeRSApayload({snonce: @last_snonce+1, cnonce: @last_cnonce}, @key, @server_key)

    as_txt = command.to_s
    as_txt = JSON.dump(command) if command.is_a?(Hash)

    ciphertext = CryptoUtils::encryptAES(as_txt, @sessionkey, @sessioniv)

    payload[:command] = Base64.strict_encode64(ciphertext)

    socket.puts(JSON.dump(payload))
  end

  def set(id, text)
    send_command(@socket, {action: 'set', id: id, text: text})
    p = receive_ready(@socket)
    return p['response'] == 0
  end

  def get(id)
    send_command(@socket, {action: 'get', id: id})
    p = receive_ready(@socket)
    if not p['response'] == 0
      return p
    else
      return nil
    end
  end


end

current_dir = File.dirname(__FILE__)

cnf = YAML::load_file(File.join(current_dir, 'client.yml'))
$log.info "Starting client with #{cnf}"
$log.level = Logger.const_get(cnf['log_level']) if cnf.has_key? 'log_level'

c = Client.new(cnf['id'], File.join(current_dir, 'keyring'))
c.authenticate(cnf['server'], cnf['port'])

puts c.set('007', 'Bond,James,High Priority')

puts c.get('007')

c.close()



