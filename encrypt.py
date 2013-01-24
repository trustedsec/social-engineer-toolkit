from Crypto.Cipher import AES

def EncryptAES(secret, data):

        # the character used for padding--with a block cipher such as AES, the value
        # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
        # used to ensure that your value is always a multiple of BLOCK_SIZE
        PADDING = '{'

        BLOCK_SIZE = 32

        # one-liner to sufficiently pad the text to be encrypted
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

        # random value here to randomize builds
        a = 50 * 5

        # one-liners to encrypt/encode and decrypt/decode a string
        # encrypt with AES, encode with base64
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

        #secret = os.urandom(BLOCK_SIZE)
        cipher = AES.new(secret)

        aes = EncodeAES(cipher, data)
        return aes

secret = os.urandom(32)
fileopen = file("social-engineer-toolkit/src/payloads/set_payloads/multi_pyinjector.binary", "rb")
data = fileopen.read()
encrypted_blob = EncryptAES(secret, data)
filewrite = file("multi_pyinjector.encrypted", "wb")
