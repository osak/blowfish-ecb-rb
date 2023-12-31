require_relative '../blowfish_ecb'
require 'yaml'

config = YAML.load(File.open(ARGV[0]))
key = config['UserConfig::account_crypt_key']
data = File.read(ARGV[1], encoding: Encoding::ASCII_8BIT)
puts Blowfish::ECB::Cipher.new(key).decrypt(data)