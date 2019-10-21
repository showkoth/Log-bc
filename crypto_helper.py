from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

key_bytes = 32
# BS = 16
# pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
# unpad = lambda s: s[:-ord(s[len(s) - 1:])]
#


# class AESCipher(object):
#     def __init__(self, key):
#         self.bs = AES.block_size
#         self.key = hashlib.sha256(key.encode()).digest()
#
#     def encrypt(self, raw):
#         raw = self._pad(raw)
#         print(type(raw), raw)
#         iv = Random.new().read(AES.block_size)
#         print("iv = ", iv)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         print(cipher.encrypt(raw))
#         return iv + cipher.encrypt(raw)
#         # return base64.b64encode(iv + cipher.encrypt(raw))
#
#     def decrypt(self, enc):
#         enc = base64.b64decode(enc)
#         iv = enc[:AES.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
#
#     def _pad(self, s):
#         print(type(s))
#         return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
#
#     @staticmethod
#     def _unpad(s):
#         return s[:-ord(s[len(s)-1:])]

# Takes as input a 32-byte key and an arbitrary-length plaintext and returns a
# pair (iv, ciphertext). "iv" stands for initialization vector.
def encrypt(key, plaintext):
    assert len(key) == key_bytes

    # Choose a random, 16-byte IV.
    iv = Random.new().read(AES.block_size)

    # Convert the IV to a Python integer.
    iv_int = int(binascii.hexlify(iv), 16)

    # Create a new Counter object with IV = iv_int.
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Encrypt and return IV and ciphertext.
    ciphertext = cipher.encrypt(plaintext)
    # return iv, ciphertext
    return base64.b64encode(iv + ciphertext)


# Takes as input a 32-byte key, a 16-byte IV, and a ciphertext, and outputs the
# corresponding plaintext.
def decrypt(key, ciphertext):
    # decrypt(key, iv, ciphertext):
    assert len(key) == key_bytes
    enc = base64.b64decode(ciphertext)
    iv = enc[:AES.block_size]
    # Initialize counter for decryption. iv should be the same as the output of
    # encrypt().
    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt and return the plaintext.
    # plaintext = aes.decrypt(ciphertext)
    plaintext = aes.decrypt(enc[AES.block_size:])
    return plaintext


def get_random_key():
    return Random.new().read(key_bytes)


def get_key_from_password(password):
    # It's also possible to derive a key from a password, but it's important that
    # the password have high entropy, meaning difficult to predict.
    # For added # security, we add a "salt", which increases the entropy.
    # In this example, we use the same RNG to produce the salt that we used to
    # produce key1.
    salt_bytes = 8
    salt = Random.new().read(salt_bytes)
    # Stands for "Password-based key derivation function 2"
    key = PBKDF2(password, salt, key_bytes)
    return key


# key = get_random_key()
# (iv, ciphertext) = encrypt(key, 'hella')
# print (decrypt(key, iv, ciphertext))


def generate_rsa_key_pair(bits=2048):
    rand = Random.new().read
    key = RSA.generate(bits, rand)
    private_key = key.exportKey('PEM')
    public_key = key.publickey().exportKey('PEM')
    # print(type(private_key), public_key)
    return private_key, public_key


def encrypt_aes_key(pubkey, aes_key):
    '''

    :param pubkey: public key in .pem format (byte) that will be used for encrypting the password
    :param aes_key: aes_key(byte-object) which is used for aes encryption
    :return: encrypted key as byte object

    '''
    public_key = RSA.import_key(pubkey)
    encryptor = PKCS1_OAEP.new(public_key)
    enc_key = encryptor.encrypt(aes_key)

    return enc_key


def decrypt_aes_key(privkey, key_cipher):
    '''

    :param privkey: private key for decryption in .pem byte format
    :param key_cipher: cipher to decrypt represented as byte object
    :return: aes_key as byte object
    '''
    private_key = RSA.import_key(privkey)
    decryptor = PKCS1_OAEP.new(private_key)
    dec_key = decryptor.decrypt(key_cipher)

    return dec_key


# print(private_key.decode('utf-8'))
# print(public_key.decode('utf-8'))
# print(type(private_key),private_key)
# private_key_hex = binascii.hexlify(private_key)
# print(type(private_key_hex), private_key_hex)
# print(binascii.unhexlify(private_key_hex))

# print(Random.get_random_bytes(16))

# print(base64.b64encode("eururir".encode())
#
# password = get_key_from_password("pass")
# print(password)
#
# private_key, pubkey = generate_rsa_key_pair()
# private = RSA.import_key(private_key)
# public = RSA.import_key(pubkey)
#
# print(pubkey)
#
# aes_key = get_random_key()
# print(len(aes_key))
# aes_key_hex = binascii.hexlify(aes_key)
# tmp = binascii.unhexlify(aes_key_hex)
# print("aes_key", len(tmp), tmp)
# encryptor = PKCS1_OAEP.new(public)
# cipher = encryptor.encrypt(aes_key)
# print("cipher =  ",cipher)
# print(type(cipher))
# decryptor = PKCS1_OAEP.new(private)
# decrypted_message = decryptor.decrypt(cipher)
# print("decrypted",decrypted_message)
#
# print(AES.block_size)
# key = get_random_key()
# cipher = encrypt(key, b'ffffffffffffffffffffffffffffffffffffffffffffffffffff\nshowkotoiewyuyiutyiuwtyiuwtyuiwtyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyiwhhhhhhhhhhhhhhhhhhhhhhhhhhh')
#
# print( cipher)
# print(decrypt(key, cipher))
#
# print(get_random_key())