require_relative 'ecb'
require_relative 'key'

module Blowfish::ECB
  class Cipher
    # call-seq:
    #   Blowfish::ECB::Cipher.new(string) -> Cipher
    #
    # Creates a Cipher instance with given key.
    def initialize(key)
      @key = Blowfish::ECB::Key.new(key)
    end

    # call-seq:
    #   cipher.encrypt(string) -> string
    #
    # Encrypts given data.
    def encrypt(data)
      if data.encoding != Encoding::ASCII_8BIT
        raise "data.encoding must be ASCII-8BIT, but got: #{data.encoding}"
      end

      pad_len = data.size - (data.size % 8)
      pad_data = ([pad_len] * pad_len).pack("C*")
      Blowfish::ECB.encrypt(data + pad_data, @key)
    end

    # call-seq:
    #   cipher.decrypt(string) -> string
    #
    # Decrypts given data.
    def decrypt(data)
      if data.encoding != Encoding::ASCII_8BIT
        raise "data.encoding must be ASCII-8BIT, but got: #{data.encoding}"
      end

      decoded = Blowfish::ECB.decrypt(data, @key)

      # Last byte indicates the size of padding.
      # Strip the padding from res accordingly.
      pad_len = decoded[-1].unpack("C")[0]
      decoded[0...-pad_len]
    end
  end
end
