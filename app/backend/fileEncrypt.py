from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import uuid
import os
def encrypt_file_with_key(public_key, file_to_encrypt):
    # Read public key from file
    tempdatafile=file_to_encrypt
    public_key = RSA.import_key(public_key)
    file_name = str(uuid.uuid4())
    file_extension = os.path.splitext(file_to_encrypt)[1]
    # Create symmetric key
    symmetric_key = b'\xd1\xa4\x8e\x11\xe4\x91z\xffG!:\x1e\xb5\xe1\x07\xb7'  # For example, a fixed key

    # Create AES cipher object for encryption
    aes_cipher = AES.new(symmetric_key, AES.MODE_EAX)
    file_to_encrypt="files/"+file_to_encrypt

    with open(file_to_encrypt, "rb") as f:
        file_data = f.read()
        ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)

    encrypted_file = "files/"+file_name+file_extension  # Name of the encrypted file
    with open(encrypted_file, "wb") as ef:
        [ef.write(x) for x in (aes_cipher.nonce, tag, ciphertext)]

    # Encrypting encrypted symmetric key with RSA
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_symmetric_key = rsa_cipher.encrypt(symmetric_key)

    encrypted_key_file = "files/"+file_name +".bin"  # Name of the encrypted key file
    with open(encrypted_key_file, "wb") as ekf:
        ekf.write(encrypted_symmetric_key)
    result=file_name+file_extension
    return result

