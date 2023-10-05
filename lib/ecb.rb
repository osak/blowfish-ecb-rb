module Blowfish::ECB
  class << self
    # call-seq:
    #   Blowfish::ECB.encrypt(string, Key) -> string
    #
    # Encrypts the data (as in byte sequence) with given key.
    # Since the data is a byte sequence, its encoding must be ASCII-8BIT. 
    def encrypt(data, key)
      if data.size % 8 != 0
        raise "data size must be multiple of 8, but got: #{data.size}"
      end

      res = ""
      0.step(data.size - 1, 8).each do |i|
        l, r = data.byteslice(i, 8).unpack("I>I>")
        res += Common.encrypt(l, r, key).pack("I>I>")
      end
      res
    end

    # call-seq:
    #   Blowfish::ECB.decrypt(string, Key) -> string
    #
    # Decrypts the data (as in byte sequence) with given key.
    # Since the data is a byte sequence, its encoding must be ASCII-8BIT. 
    def decrypt(data, key)
      if data.encoding != Encoding::ASCII_8BIT
        raise "data.encoding must be ASCII-8BIT, but got: #{data.encoding}"
      end
      if data.size % 8 != 0
        raise "data size must be multiple of 8, but got: #{data.size}"
      end

      res = ""
      0.step(data.size - 1, 8).each do |i|
        l, r = data.byteslice(i, 8).unpack("I>I>")
        res += Common.decrypt(l, r, key).pack("I>I>")
      end
      res
    end
  end
end