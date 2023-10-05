require 'test/unit'
require 'blowfish_ecb'

class CipherTest < Test::Unit::TestCase
  def test_identity
    cipher = Blowfish::ECB::Cipher.new("cipher_test")
    ["hogefugahige", "1234567890", (1..255).to_a.pack("C*"), "", "1", "あえいうえおあお"].each do |data|
      assert_equal(data.force_encoding(Encoding::ASCII_8BIT), cipher.decrypt(cipher.encrypt(data)), "Failed at #{data}")
    end
  end
end