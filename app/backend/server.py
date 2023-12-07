from flask import Flask, jsonify, request, make_response
from key_genarator import generate_key_pair
from message_processing import encrypt_message,decrypt_message

app = Flask(__name__)

@app.route('/api/get_keys', methods=['GET'])
def get_keys():
    private_key, public_key = generate_key_pair()
    return jsonify({'private_key': private_key.decode(), 'public_key': public_key.decode()})

@app.route('/api/encrypt_message', methods=['POST'])
def encrypt_message_route():
    data = request.get_json()
    publickey = data.get('publickey')
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


if __name__ == '__main__':
    app.run(debug=True)
