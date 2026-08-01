def encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr((ord(char) - ord('A') + key) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') + key) % 26 + ord('a'))
        else:
            result += char
    return result
def decrypt(text, key):
    return encrypt(text, -key)
plaintext = input("Enter Plaintext: ")
key = int(input("Enter Key (1-25): "))
cipher = encrypt(plaintext, key)
print("Encrypted Text:", cipher)
plain = decrypt(cipher, key)
print("Decrypted Text:", plain)
