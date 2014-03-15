require 'openssl'

key = OpenSSL::PKey::RSA.new 2048

puts key.to_pem
puts ''
puts key.public_key.to_pem