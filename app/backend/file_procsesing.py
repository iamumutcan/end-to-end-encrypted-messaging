def save_to_file(text, filename):
    with open(filename, "wb") as f:
        f.write(text)

def read_from_file(filename):
    with open(filename, "rb") as f:
        key = f.read()
    return key