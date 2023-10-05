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
      bytes = data.unpack("C*")
      pad_len = 8 - (bytes.size % 8)
      bytes.push(*([pad_len] * pad_len))
      Blowfish::ECB.encrypt(bytes.pack("C*"), @key)
    end

    # call-seq:
    #   cipher.decrypt(string) -> string
    #
    # Decrypts given data. The data must be in ASCII-8BIT encoding, since the
    # encrypted data consists of arbitrary bytes. It is a sign of a bug if the
    # encrypted data is encoded as if it was a human-readable text.
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
