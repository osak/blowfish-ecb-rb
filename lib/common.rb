module Blowfish::ECB::Common
  class << self
    # call-seq:
    #   encrypt(l, r, Key) -> [int, int]
    #
    # Encrypts pseudo-64bit-value (l, r) into bytes using given key.
    # Both l and r must be 32-bit integers.
    # Original: https://github.com/openssl/openssl/blob/e8e2b131ca253f9e28c511c8294e27ddbd0b60c6/crypto/bf/bf_enc.c#L30
    #
    # Note that unlike the original implementation, this method returns a new tuple representing the result
    # rather than destructively updating the input argument. 
    def encrypt(l, r, key)
      l ^= key.p[0]
      r = bf_enc(r, l, key.s, key.p[1])
      l = bf_enc(l, r, key.s, key.p[2])
      r = bf_enc(r, l, key.s, key.p[3])
      l = bf_enc(l, r, key.s, key.p[4])
      r = bf_enc(r, l, key.s, key.p[5])
      l = bf_enc(l, r, key.s, key.p[6])
      r = bf_enc(r, l, key.s, key.p[7])
      l = bf_enc(l, r, key.s, key.p[8])
      r = bf_enc(r, l, key.s, key.p[9])
      l = bf_enc(l, r, key.s, key.p[10])
      r = bf_enc(r, l, key.s, key.p[11])
      l = bf_enc(l, r, key.s, key.p[12])
      r = bf_enc(r, l, key.s, key.p[13])
      l = bf_enc(l, r, key.s, key.p[14])
      r = bf_enc(r, l, key.s, key.p[15])
      l = bf_enc(l, r, key.s, key.p[16])
      r ^= key.p[17]

      [r & 0xffffffff, l & 0xffffffff]
    end

    # call-seq:
    #   decrypt(l, r, Key) -> [int, int]
    #
    # Decrypts pseudo-64bit-value (l, r) into bytes using given key.
    # Both l and r must be 32-bit integers.
    # Original: https://github.com/openssl/openssl/blob/e8e2b131ca253f9e28c511c8294e27ddbd0b60c6/crypto/bf/bf_enc.c#L69
    #
    # Note that unlike the original implementation, this method returns a new tuple representing the result
    # rather than destructively updating the input argument. 
    def decrypt(l, r, key)
      l ^= key.p[17]
      r = bf_enc(r, l, key.s, key.p[16])
      l = bf_enc(l, r, key.s, key.p[15])
      r = bf_enc(r, l, key.s, key.p[14])
      l = bf_enc(l, r, key.s, key.p[13])
      r = bf_enc(r, l, key.s, key.p[12])
      l = bf_enc(l, r, key.s, key.p[11])
      r = bf_enc(r, l, key.s, key.p[10])
      l = bf_enc(l, r, key.s, key.p[9])
      r = bf_enc(r, l, key.s, key.p[8])
      l = bf_enc(l, r, key.s, key.p[7])
      r = bf_enc(r, l, key.s, key.p[6])
      l = bf_enc(l, r, key.s, key.p[5])
      r = bf_enc(r, l, key.s, key.p[4])
      l = bf_enc(l, r, key.s, key.p[3])
      r = bf_enc(r, l, key.s, key.p[2])
      l = bf_enc(l, r, key.s, key.p[1])
      r ^= key.p[0]

      [r & 0xffffffff, l & 0xffffffff]
    end

    private

    # call-seq:
    #    bf_enc(int, int, [int], int) -> int
    #
    # Calculates one step of the Blowfish encryption.
    # Original: https://github.com/openssl/openssl/blob/e8e2b131ca253f9e28c511c8294e27ddbd0b60c6/crypto/bf/bf_local.h#L76
    #
    # Note that due to limitation in Ruby, unlike what the original BF_ENC is doing,
    # this method returns the calculated value rather than destructively reassigning l.
    def bf_enc(l, r, s, p)
      tmp =  s[0x0000+((r>>24)&0xff)]
      tmp += s[0x0100+((r>>16)&0xff)]
      tmp ^= s[0x0200+((r>> 8)&0xff)]
      tmp += s[0x0300+((r    )&0xff)]
      l ^ p ^ (tmp & 0xffffffff)
    end
  end
end