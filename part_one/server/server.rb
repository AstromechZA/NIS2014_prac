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

class Server

  def initialize(keyring_dir, data_dir)
    @keyring_dir = keyring_dir
    @data_dir = data_dir
    Dir.mkdir(@data_dir) if not File.exists?(@data_dir)
    @key = CryptoUtils::load_key File.join(@keyring_dir, 'self.pem')
  end

  def key_exists?(file)
    File.exists?(File.join(@keyring_dir, file))
  end

  def start(port)
    $log.info "Listening on #{port}"
    server = TCPServer.open(port)

    loop {
      Thread.start(server.accept) do |socket|
        $log.info "Accepted connection from #{socket.remote_address.ip_address}:#{socket.remote_address.ip_port}"
        begin
          client = receive_handshake(socket)

          send_affirmation(socket, client)

          receive_confirmation(socket, client)

          send_ready(socket, client)

          while true
            request = receive_command(socket, client)

            $log.info "Received command: #{request['action']}"

            if request['action'] == 'quit'
              break
            end

            response = perform(client, request)

            send_response(socket, client, response)
          end

        rescue Exception => e
          $log.error "#{e.message}"
        end
        $log.info "Closing connection to #{socket.remote_address.ip_address}:#{socket.remote_address.ip_port}"
        socket.close
      end
    }
  end

  def receive_handshake(socket)
    $log.debug 'Waiting for handshake'
    data = JSON.load(socket.gets)

    payload = JSON.load(@key.private_decrypt(Base64.decode64(data['payload'])))
    client = {
      id: payload['id'],
      cnonce: payload['cnonce'],
      key: CryptoUtils::load_key(File.join(@keyring_dir, "#{payload['id']}.pem"))
    }

    CryptoUtils::checkRSApayloadSignature(data, @key, client[:key])

    return client
  end

  def send_affirmation(socket, client)
    $log.debug 'Sending affirmation'
    client[:snonce] = Random.rand(2**31)

    k, iv = CryptoUtils::generateAESPair

    client[:sessionkey] = k
    client[:sessioniv] = iv

    payload = CryptoUtils::makeRSApayload(
      {
        cnonce: client[:cnonce]+1,
        snonce: client[:snonce],
        sessionkey: Base64.strict_encode64(k),
        iv: Base64.strict_encode64(iv)
      },
      @key,
      client[:key]
    )

    socket.puts(JSON.dump(payload))
  end

  def receive_confirmation(socket, client)
    $log.debug 'Waiting for confirmation and command'
    data = JSON.load(socket.gets)

    payload = CryptoUtils::checkRSApayloadSignature(data, @key, client[:key])

    valid = (client[:snonce] + 1) == payload['snonce']
    raise 'nonce error' if not valid

    $log.info('Client is now trusted. (auth + fresh)')

    plaintext = CryptoUtils::decryptAES(Base64.decode64(data['check']), client[:sessionkey], client[:sessioniv])

    raise 'aes check error' if not plaintext == 'abcdefghijklmnopqrstuvwxyz'

    client[:cnonce] = payload['cnonce']
  end

  def send_ready(socket, client)
    $log.debug 'Sending Ready'
    client[:snonce] = Random.rand(2**31)

    response = JSON.dump({response: 0, message: 'ready', cnonce: client[:cnonce]+1, snonce: client[:snonce]})

    ciphertext = CryptoUtils::encryptAES(response, client[:sessionkey], client[:sessioniv])

    secure_response = Base64.strict_encode64(ciphertext)

    socket.puts(secure_response)
  end

  def receive_command(socket, client)
    $log.debug 'Waiting for command'
    data = JSON.load(socket.gets)

    payload = CryptoUtils::checkRSApayloadSignature(data, @key, client[:key])

    valid = (client[:snonce] + 1) == payload['snonce']
    raise 'nonce error' if not valid

    plaintext = CryptoUtils::decryptAES(Base64.decode64(data['command']), client[:sessionkey], client[:sessioniv])

    client[:cnonce] = payload['cnonce']

    return JSON.load(plaintext)
  end

  def send_response(socket, client, response)
    $log.debug "Sending response"
    client[:snonce] = Random.rand(2**31)

    response[:cnonce] = client[:cnonce] + 1
    response[:snonce] = client[:snonce]

    response = JSON.dump(response)

    ciphertext = CryptoUtils::encryptAES(response, client[:sessionkey], client[:sessioniv])

    secure_response = Base64.strict_encode64(ciphertext)

    socket.puts(secure_response)
  end

  def upload(client, lines)
    f = File.join(@data_dir, 'customers.dat')

    # load lines from json
    contents_a = JSON.load(lines)

    # overwrite the file
    File.open(f, 'w') do |io|
      # write all the lines
      contents_a.each do |line|

        # append signed line hash
        line_h = OpenSSL::Digest::SHA1.digest(line)
        signed_line_h = @key.private_encrypt(line_h)
        signed_line_he = Base64.strict_encode64(signed_line_h)
        line += "||#{signed_line_he}"

        io.puts line
      end
    end

    # return response
    return {response: 0, message: "Stored #{contents_a.length} lines"}
  end

  def get(client, id)
    # check if file exists
    f = File.join(@data_dir, 'customers.dat')
    if File.exists?(f)

      # read lines in
      lines = File.readlines(f)

      # search for item
      lines.each do |line|
        line = line.chomp
        parts = line.split('||')
        # find matching line
        if parts[0].upcase == id.upcase

          # check integrity
          signed_line_he = parts[3]
          signed_line_h = Base64.decode64(signed_line_he)
          line_h = @key.public_decrypt(signed_line_h)

          # reconstruct line
          l = parts[0,3].join('||')

          # rehash
          line_rehash = OpenSSL::Digest::SHA1.digest(l)

          # check
          return {response: 1, message: 'record corrupted'} if not line_h == line_rehash

          return {response: 0, message: 'record found', details: parts[1]}
        end
      end
    end
    return {response: 1, message: "no data available"}
  end

  def hash_check(client, id, hash)
    # check if file exists
    f = File.join(@data_dir, 'customers.dat')
    if File.exists?(f)

      # read lines in
      lines = File.readlines(f)

      # search for item
      lines.each do |line|
        line = line.chomp
        parts = line.split('||')
        if parts[0].upcase == id.upcase

          # check integrity
          signed_line_he = parts[3]
          signed_line_h = Base64.decode64(signed_line_he)
          line_h = @key.public_decrypt(signed_line_h)

          # reconstruct line
          l = parts[0,3].join('||')

          # rehash
          line_rehash = OpenSSL::Digest::SHA1.digest(l)

          # check
          return {response: 1, message: 'record corrupted'} if not line_h == line_rehash

          return {response: 0, message: 'record found', correct: parts[2] == hash}
        end
      end
    end
    return {response: 1, message: "no data available"}
  end

  def perform(client, cmd)
    if cmd.include? 'action'
      case cmd['action']
      when 'upload'
        return upload(client, cmd['lines'])
      when 'get'
        return get(client, cmd['id'])
      when 'hash_check'
        return hash_check(client, cmd['id'], cmd['hash'])
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
$log.info "Starting server with #{cnf}"
$log.level = Logger.const_get(cnf['log_level']) if cnf.has_key? 'log_level'

keyring_dir = File.join(current_dir, 'keyring')
data_dir = File.join(current_dir, 'data')

s = Server.new(keyring_dir, data_dir)
s.start(cnf['listenPort'])
