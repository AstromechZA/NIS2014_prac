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

    send_handshake(@socket)

    receive_affirmation(@socket)

    send_confirmation(@socket)

    receive_responce(@socket)
  end

  def close
    send_command(@socket, {action: 'quit'})
    $log.debug 'Closing socket'
    @socket.close
  end


  # handshake message
  # Identifies the client to the server
  def send_handshake(socket)
    $log.debug 'Sending handshake'
    @last_cnonce = Random.rand(2**31)
    # construct payload with signed version
    payload = CryptoUtils::makeRSApayload({id: @id, cnonce: @last_cnonce}, @key, @server_key)
    # send to server
    socket.puts(JSON.dump(payload))
  end

  # affirmation message
  # Server sends back incremented client nonce, server nonce, and a master key+iv
  def receive_affirmation(socket)
    $log.debug 'Waiting for affirmation'
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
    $log.debug 'Sending confirmation'
    @last_cnonce = Random.rand(2**31)

    payload = CryptoUtils::makeRSApayload({snonce: @last_snonce+1, cnonce: @last_cnonce}, @key, @server_key)

    ciphertext = CryptoUtils::encryptAES('abcdefghijklmnopqrstuvwxyz', @sessionkey, @sessioniv)

    payload[:check] = Base64.strict_encode64(ciphertext)

    socket.puts(JSON.dump(payload))
  end

  def receive_responce(socket)
    $log.debug 'Waiting for response'
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
    $log.info "Sending command: #{command[:action]}"
    @last_cnonce = Random.rand(2**31)

    payload = CryptoUtils::makeRSApayload({snonce: @last_snonce+1, cnonce: @last_cnonce}, @key, @server_key)

    as_txt = command.to_s
    as_txt = JSON.dump(command) if command.is_a?(Hash)

    ciphertext = CryptoUtils::encryptAES(as_txt, @sessionkey, @sessioniv)

    payload[:command] = Base64.strict_encode64(ciphertext)

    socket.puts(JSON.dump(payload))
  end

  def secure_upload(file)
    # array of secure lines
    contents_a = []

    # read the symmetric key in
    aes_k, aes_iv = CryptoUtils::readAESPairFromFile(File.join(@keyring, 'file_key.aes'))

    # for each line in the customers file
    File.readlines(file).each do |line|
      # split id and details
      id, details = line.split('-', 2)

      # chomp newline char
      details = details.chomp

      # create a correct hash and encode it
      hbit = "#{id}||#{details}"
      hbit_h = OpenSSL::Digest::SHA1.digest(hbit)
      hbit_he = Base64.strict_encode64(hbit_h)

      # encrypt the details with the symmetric key, and encode
      secure_details = CryptoUtils::encryptAES(details, aes_k, aes_iv)
      secure_details_e = Base64.strict_encode64(secure_details)

      # add the line to contents
      contents_a << "#{id}||#{secure_details_e}||#{hbit_he}"
    end

    # encode as json for transfer
    contents_aj = JSON.dump(contents_a)

    # send it!
    send_command(@socket, {action: 'upload', lines: contents_aj})
    p = receive_responce(@socket)
    return p['response'] == 0
  end


  def get(id)
    send_command(@socket, {action: 'get', id: id})
    p = receive_responce(@socket)
    if p['response'] == 0

      # decode
      secure_details_e = p['details']
      secure_details = Base64.decode64(secure_details_e)

      # read aes key
      aes_k, aes_iv = CryptoUtils::readAESPairFromFile(File.join(@keyring, 'file_key.aes'))

      # decrypt
      details = CryptoUtils::decryptAES(secure_details, aes_k, aes_iv)

      # return
      return details
    else
      return nil
    end
  end

  def hash_check(id, details)
    return hash_check_raw(id, OpenSSL::Digest::SHA1.digest("#{id}||#{details}"))
  end

  def hash_check_raw(id, hash)
    # encode the hash
    hash_e = Base64.strict_encode64(hash)

    # send it
    send_command(@socket, {action: 'hash_check', id: id, hash: hash_e})
    p = receive_responce(@socket)
    if p['response'] == 0
      return p['correct']
    else
      return nil
    end
  end


end

current_dir = File.dirname(__FILE__)

cnf = YAML::load_file(File.join(current_dir, 'client.yml'))
$log.level = Logger.const_get(cnf['log_level']) if cnf.has_key? 'log_level'

c = Client.new(cnf['id'], File.join(current_dir, 'keyring'))

puts 'Authenticating with server'
c.authenticate(cnf['server'], cnf['port'])

puts ''
puts 'Uploading customers file'
puts c.secure_upload(File.join(current_dir, 'customers.dat'))

puts ''
puts 'Getting data for ID007'
d = c.get('ID007')
puts d.inspect

puts ''
puts 'Checking that data matches remote data'
puts c.hash_check('ID007', d)

puts c.hash_check('ID002', 'Meier,Ben,Secondary Asset')

puts ''
puts 'Getting an unknown record'
puts c.get('ID004').inspect

puts ''
puts 'Closing'
c.close()



