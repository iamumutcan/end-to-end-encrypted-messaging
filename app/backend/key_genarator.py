from Crypto.PublicKey import RSA
import file_procsesing
def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


private_key, public_key = generate_key_pair()



# Save keys to file
#   file_procsesing.save_to_file(private_key, "private_key.pem")
#   file_procsesing.save_to_file(public_key, "public_key.pem")



