require 'json'
require 'base64'
require 'openssl'

module CryptoUtils


  def load_key(path)
    OpenSSL::PKey::RSA.new(File.read(path))
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

  def encryptAES(string, key, iv)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    return cipher.update(string) + cipher.final
  end

  def decryptAES(bytes, key, iv)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv

    return cipher.update(bytes) + cipher.final
  end

  module_function :load_key
  module_function :makeRSApayload
  module_function :checkRSApayloadSignature
  module_function :encryptAES
  module_function :decryptAES
end