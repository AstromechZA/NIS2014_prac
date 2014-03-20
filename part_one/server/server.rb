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

            response = perform(request)

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




  def set(id, document)
    f = File.join(@data_dir, id)
    m = /(ID)?(\d{3})/i.match(id)
    if not m
      return {response: 1, message: "Invalid id #{id}"}
    else

      return {response: 0, message: "Stored #{m[2]}"}
    end
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
        return set(cmd['id'], cmd['document'])
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
$log.info "Starting server with #{cnf}"
$log.level = Logger.const_get(cnf['log_level']) if cnf.has_key? 'log_level'

keyring_dir = File.join(current_dir, 'keyring')
data_dir = File.join(current_dir, 'data')

s = Server.new(keyring_dir, data_dir)
s.start(cnf['listenPort'])
