from flask import Flask, jsonify, request, send_file
from key_genarator import generate_key_pair
from message_processing import encrypt_message,decrypt_message
from fileEncrypt import encrypt_file_with_key
from fileDecrypt import decrypt_file_with_key

import os
import uuid
app = Flask(__name__)

@app.route('/api/get_keys', methods=['GET'])
def get_keys():
    private_key, public_key = generate_key_pair()
    return jsonify({'private_key': private_key.decode(), 'public_key': public_key.decode()})

@app.route('/api/<path:file_name>')
def get_file(file_name):
    file_path = f'files/decrypt/{file_name}'
    return send_file(file_path, as_attachment=True)

@app.route('/api/encrypt_message', methods=['POST'])
def encrypt_message_route():
    data = request.get_json()
    publickey = data.get('public_key')
    message = data.get('message')
    # Assuming publickey is in string format and needs encoding
    publickey_bytes = publickey.encode()  # Encode string to bytes
    encryptmessage = encrypt_message(message, publickey_bytes)
    # Convert encrypted message to a hex string
    encrypted_hex_string = encryptmessage.hex()
    return jsonify({'encrypt_message': encrypted_hex_string})

@app.route('/api/decrypt_message', methods=['POST'])
def decrypt_message_route():
    data = request.get_json()
    encrypted_message_hex = data.get('message')
    private_key_str = data.get('private_key')
    encrypted_message = bytes.fromhex(encrypted_message_hex)
    decrypted_message = decrypt_message(encrypted_message, private_key_str)
    return jsonify({'decrypted_message': decrypted_message})

@app.route('/api/test', methods=['POST'])
def aaa():
    data = request.get_json()
    publickey = data.get('public_key')
    message = data.get('message')
    # Assuming publickey is in string format and needs encoding
    publickey_bytes = publickey.encode()  # Encode string to bytes
    encryptmessage = encrypt_message(message, publickey_bytes)
    # Convert encrypted message to a hex string
    #encrypted_hex_string = encryptmessage.hex()
    return jsonify({'encrypt_message': publickey_bytes.hex()})

@app.route('/api/file-upload', methods=['POST'])
def file_upload():
    if 'dosya' not in request.files:
        return 'Dosya yok'

    file = request.files['dosya']

    if file.filename == '':
        return 'Dosya seçilmedi'

    if file:
        file_name = str(uuid.uuid4())
        file_extension = os.path.splitext(file.filename)[1]
        file.save(os.path.join('files/temp/', file_name+file_extension))
        return jsonify({'upload_file_path': file_name+file_extension})

    return 'Bir hata oluştu'

@app.route('/api/file-encrypt', methods=['POST'])
def file_Encrypt():
    data = request.get_json()
    print(data)
    publickey = data.get('public_key')
    file_path = 'temp/'+data.get('file_path')
    publickey_bytes = publickey.encode()  # Encode string to bytes

    encryptfile = encrypt_file_with_key(publickey_bytes, file_path)
    # Convert encrypted message to a hex string
    return jsonify({'encrypt_file_path': encryptfile})

@app.route('/api/file-decrypt', methods=['POST'])
def file_Decrypt():
    data = request.get_json()
    print(data)
    privatekey = data.get('private_key')
    file_path = data.get('file_path')
    privatekey_bytes = privatekey.encode()  # Encode string to bytes

    encryptfile = decrypt_file_with_key(privatekey_bytes, file_path)
    # Convert encrypted message to a hex string
    return jsonify({'decrypt_file_path': r'http://127.0.0.1:5000/api/'+encryptfile})


if __name__ == '__main__':
    app.run(debug=True)
