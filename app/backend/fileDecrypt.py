from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import uuid

def decrypt_file_with_key(private_key, filepath):
    private_key = RSA.import_key(private_key)
    file_extension = os.path.splitext(filepath)[1]
    file_path_for_bin= os.path.splitext(filepath)[0]
    file_name = str(uuid.uuid4())

    # Decrypt encrypted symmetric key with RSA
    encrypted_key_file = "files/"+file_path_for_bin+".bin"  # Name of the encrypted key file
    with open(encrypted_key_file, "rb") as ekf:
        encrypted_symmetric_key = ekf.read()

    rsa_cipher = PKCS1_OAEP.new(private_key)
    symmetric_key = rsa_cipher.decrypt(encrypted_symmetric_key)

    # Decode file using AES
    encrypted_file = "files/"+filepath # Name of the encrypted file
    with open(encrypted_file, "rb") as ef:
        nonce, tag, ciphertext = [ef.read(x) for x in (16, 16, -1)]

    aes_cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce)
    file_data = aes_cipher.decrypt_and_verify(ciphertext, tag)

    decrypted_file = "files/decrypt/"+file_name+file_extension  # Name of decrypted file
    with open(decrypted_file, "wb") as df:
        df.write(file_data)

    result = file_name + file_extension
    return result

