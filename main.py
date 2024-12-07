import random
import string
import math
import subprocess

# Key generation functions

def generate_caesar_key():
    return random.randint(1, 25)

def generate_affine_key():
    while True:
        a = random.randint(1, 25)
        if math.gcd(a, 26) == 1:  
            b = random.randint(0, 25)
            return a, b

def generate_monoalphabetic_key():
    alphabet = list(string.ascii_lowercase)
    shuffled_alphabet = alphabet[:]
    random.shuffle(shuffled_alphabet)
    return dict(zip(alphabet, shuffled_alphabet)), dict(zip(shuffled_alphabet, alphabet))

def generate_polyalphabetic_key(length=8):
    characters = string.ascii_lowercase
    return ''.join(random.choice(characters) for _ in range(length))

def save_to_file(filename, content):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)

# Caesar cipher encrypt and decrypt

def caesar_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            shift = ord(char) + key
            result += chr(shift - 26) if (char.islower() and shift > ord('z')) or (char.isupper() and shift > ord('Z')) else chr(shift)
        else:
            result += char
    return result

def caesar_decrypt(text, key):
    return ''.join(chr((ord(c) - key - (97 if c.islower() else 65)) % 26 + (97 if c.islower() else 65)) if c.isalpha() else c for c in text)

# Affine cipher encrypt and decrypt

def affine_encrypt(text, a, b):
    return ''.join(chr((a * (ord(c) - 97) + b) % 26 + 97) if c.isalpha() else c for c in text.lower())

def affine_decrypt(cipher, a, b):
    a_inv = pow(a, -1, 26)
    return ''.join(chr((a_inv * ((ord(c) - 97) - b)) % 26 + 97) if c.isalpha() else c for c in cipher.lower())

# Monoalphabetic cipher encrypt and decrypt

def monoalphabetic_encrypt(text, key_map):
    return ''.join(key_map[c.lower()] if c.lower() in key_map else c for c in text)

def monoalphabetic_decrypt(cipher, reverse_key_map):
    return ''.join(reverse_key_map[c.lower()] if c.lower() in reverse_key_map else c for c in cipher)

# Polyalphabetic cipher encrypt and decrypt

def polyalphabetic_encrypt(text, key):
    key_length = len(key)
    return ''.join(chr((ord(c) - 97 + (ord(key[i % key_length]) - 97)) % 26 + 97) if c.isalpha() else c for i, c in enumerate(text.lower()))

def polyalphabetic_decrypt(cipher, key):
    key_length = len(key)
    return ''.join(chr((ord(c) - 97 - (ord(key[i % key_length]) - 97)) % 26 + 97) if c.isalpha() else c for i, c in enumerate(cipher.lower()))

# Hacking (Brute-force and Analysis)

def caesar_brute_force(cipher):
    results = {}
    for key in range(1, 26):
        decrypted_text = caesar_decrypt(cipher, key)
        results[key] = decrypted_text
    return results

def affine_brute_force(cipher):
    results = {}
    for a in range(1, 26):
        if math.gcd(a, 26) == 1:
            for b in range(26):
                decrypted_text = affine_decrypt(cipher, a, b)
                results[(a, b)] = decrypted_text
    return results

def monoalphabetic_frequency_analysis(cipher):
    english_freq_order = "etaoinshrdlcumwfgypbvkjxqz"
    cipher_freq_order = ''.join(sorted(set(cipher.lower()), key=lambda c: cipher.lower().count(c), reverse=True))
    mapping = dict(zip(cipher_freq_order, english_freq_order))
    decrypted_text = ''.join(mapping.get(c, c) for c in cipher.lower())
    return decrypted_text

def polyalphabetic_brute_force(cipher, key_length=3):
    results = {}
    for i in range(26 ** key_length):
        key = ''.join(chr((i // (26 ** j) % 26) + ord('a')) for j in range(key_length))
        decrypted_text = polyalphabetic_decrypt(cipher, key)
        results[key] = decrypted_text
    return results

# Main task execution

text = '''From fairest creatures we desire increase, That thereby beauty's rose might never die, But as the riper should by time decease, His tender heir might bear his memory: But thou contracted to thine own bright eyes, Feed'st thy light's flame with self-substantial fuel, Making a famine where abundance lies, Thy self thy foe, to thy sweet self too cruel: Thou that art now the world's fresh ornament, And only herald to the gaudy spring, Within thine own bud buriest thy content, And tender churl mak'st waste in niggarding: Pity the world, or else this glutton be, To eat the world's due, by the grave and thee. When forty winters shall besiege thy brow, And dig deep trenches in thy beauty's field, Thy youth's proud livery so gazed on now, Will be a tattered weed of small worth held: Then being asked, where all thy beauty lies, Where all the treasure of thy lusty days; To say within thine own deep sunken eyes, Were an all-eating shame, and thriftless praise.'''

german_text = """Wir wünschen uns, dass die schönsten Geschöpfe vermehrt werden, damit die Rose der Schönheit niemals stirbt, sondern, wenn die reifere mit der Zeit stirbt, ihre zarte Erbin ihre Erinnerung trägt. Doch du, verengtest dich zu deinen eigenen strahlenden Augen, nährst die Flamme deines Lichts mit selbststofflichem Brennstoff und verursachst eine Hungersnot, wo Überfluss herrscht. Du selbst bist dein Feind, zu grausam für dein süßes Selbst. Du, der jetzt die frische Zierde der Welt bist und der einzige Herold des bunten Frühlings, begräbst deinen Inhalt in deiner eigenen Knospe und verschwendest, du zarter Bauer, in Geiz. Hab Mitleid mit der Welt, sonst sei dieser Vielfraß, der auffrisst, was der Welt zusteht, beim Grab und bei dir. Wenn vierzig Winter deine Stirn belagern und tiefe Gräben in das Feld deiner Schönheit graben, wird das stolze Livree deiner Jugend, das man jetzt so bestaunt, nur noch ein zerfetztes Unkraut von geringem Wert sein. Dann wird die Frage, wo all deine Schönheit liegt, wo all die Schätze deiner lustvollen Tage, in deinen eigenen tief eingesunkenen Augen zu sagen, eine alles verzehrende Schande und ein verschwenderisches Lob sein..."""

# Encryptions and decryptions

# Caesar cipher
caesar_key = generate_caesar_key()
caesar_encrypted = caesar_encrypt(german_text, caesar_key)
caesar_decrypted = caesar_decrypt(caesar_encrypted, caesar_key)
save_to_file("german_caesar_encrypted.txt", caesar_encrypted)
save_to_file("german_caesar_decrypted.txt", caesar_decrypted)

# Affine cipher
affine_key_a, affine_key_b = generate_affine_key()
affine_encrypted = affine_encrypt(german_text, affine_key_a, affine_key_b)
affine_decrypted = affine_decrypt(affine_encrypted, affine_key_a, affine_key_b)
save_to_file("german_affine_encrypted.txt", affine_encrypted)
save_to_file("german_affine_decrypted.txt", affine_decrypted)

# Monoalphabetic cipher
mono_key_map, mono_reverse_key_map = generate_monoalphabetic_key()
mono_encrypted = monoalphabetic_encrypt(german_text, mono_key_map)
mono_decrypted = monoalphabetic_decrypt(mono_encrypted, mono_reverse_key_map)
save_to_file("german_mono_encrypted.txt", mono_encrypted)
save_to_file("german_mono_decrypted.txt", mono_decrypted)

# Polyalphabetic cipher
poly_key = generate_polyalphabetic_key(5)
poly_encrypted = polyalphabetic_encrypt(german_text, poly_key)
poly_decrypted = polyalphabetic_decrypt(poly_encrypted, poly_key)
save_to_file("german_poly_encrypted.txt", poly_encrypted)
save_to_file("german_poly_decrypted.txt", poly_decrypted)

# Hacking results for German text

# Caesar brute-force hack
caesar_hack_results = caesar_brute_force(caesar_encrypted)
save_to_file("german_caesar_hack_results.txt", '\n'.join(f'Key {k}: {v}' for k, v in caesar_hack_results.items()))

# Affine brute-force hack
affine_hack_results = affine_brute_force(affine_encrypted)
save_to_file("german_affine_hack_results.txt", '\n'.join(f'Key (a={k[0]}, b={k[1]}): {v}' for k, v in affine_hack_results.items()))

# Monoalphabetic frequency analysis hack
mono_hack_result = monoalphabetic_frequency_analysis(mono_encrypted)
save_to_file("german_mono_hack_result.txt", mono_hack_result)

# Polyalphabetic brute-force hack 
polyalphabetic_hack_results = polyalphabetic_brute_force(poly_encrypted, key_length=3)
save_to_file("german_poly_hack_results.txt", '\n'.join(f'Key {k}: {v}' for k, v in polyalphabetic_hack_results.items()))

#####

# Generate a 56-bit DES key 
def generate_des_key():
    key = ''.join([chr(random.randint(0, 255)) for _ in range(7)]) 
    return key

# Initial and final permutation tables 
initial_permutation_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

final_permutation_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Example S-Box 
s_box = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

# Permutation function for feistel rounds
def permute(block, table):
    padded_block = block.ljust(64, '0')
    return ''.join(padded_block[i-1] for i in table)

# XOR function for binary strings
def xor(a, b):
    return ''.join(['1' if x != y else '0' for x, y in zip(a, b)])

# S-Box Substitution function 
def s_box_substitution(block):
    if len(block) < 6:
        block = block.ljust(6, '0')
    row = int(block[0] + block[-1], 2)
    col = int(block[1:5], 2)
    return format(s_box[row][col], '04b')

# Function for each DES round
def des_round(left, right, subkey):
    expanded_right = permute(right, initial_permutation_table[:32])  
    xored = xor(expanded_right, subkey)
    
    if len(xored) % 6 != 0:
        xored = xored.ljust((len(xored) // 6 + 1) * 6, '0')
    
    substituted = ''.join([s_box_substitution(xored[i:i+6]) for i in range(0, len(xored), 6)])
    new_right = xor(left, substituted)
    return right, new_right  

# Key schedule 
def generate_subkeys(key):
    return [key] * 16  

# DES encryption function
def des_encrypt(plaintext, key):
    binary_text = ''.join(format(ord(char), '08b') for char in plaintext)
    permuted_text = permute(binary_text, initial_permutation_table)
    left, right = permuted_text[:32], permuted_text[32:]
    subkeys = generate_subkeys(key)

    for subkey in subkeys:
        left, right = des_round(left, right, subkey)
    
    combined_text = right + left
    final_text = permute(combined_text, final_permutation_table)
    return ''.join(chr(int(final_text[i:i+8], 2)) for i in range(0, len(final_text), 8))

# DES decryption function
def des_decrypt(ciphertext, key):
    binary_text = ''.join(format(ord(char), '08b') for char in ciphertext)
    permuted_text = permute(binary_text, final_permutation_table)
    left, right = permuted_text[:32], permuted_text[32:]
    subkeys = generate_subkeys(key)[::-1]

    for subkey in subkeys:
        left, right = des_round(left, right, subkey)
    
    combined_text = right + left
    final_text = permute(combined_text, initial_permutation_table)
    return ''.join(chr(int(final_text[i:i+8], 2)) for i in range(0, len(final_text), 8))

# Save to file function
def save_to_file(filename, content):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)

# Generate DES key
des_key = generate_des_key()

# Original message for encryption
message = '''From fairest creatures we desire increase, That thereby beauty's rose might never die, But as the riper should by time decease, His tender heir might bear his memory: But thou contracted to thine own bright eyes, Feed'st thy light's flame with self-substantial fuel, Making a famine where abundance lies, Thy self thy foe, to thy sweet self too cruel: Thou that art now the world's fresh ornament, And only herald to the gaudy spring, Within thine own bud buriest thy content, And tender churl mak'st waste in niggarding: Pity the world, or else this glutton be, To eat the world's due, by the grave and thee. When forty winters shall besiege thy brow, And dig deep trenches in thy beauty's field, Thy youth's proud livery so gazed on now, Will be a tattered weed of small worth held: Then being asked, where all thy beauty lies, Where all the treasure of thy lusty days; To say within thine own deep sunken eyes, Were an all-eating shame, and thriftless praise.'''

# Encrypt the message
encrypted_message = des_encrypt(message, des_key)

# Decrypt the message
decrypted_message = des_decrypt(encrypted_message, des_key)

# Save the results
save_to_file("des_encrypted_message.txt", encrypted_message)
save_to_file("des_decrypted_message.txt", decrypted_message)

# Display results
print("Original Message:", message)
print("DES Encrypted Message:", encrypted_message)
print("DES Decrypted Message:", decrypted_message)

###

# Original message for encryption
message = '''From fairest creatures we desire increase, That thereby beauty's rose might never die, But as the riper should by time decease, His tender heir might bear his memory: But thou contracted to thine own bright eyes, Feed'st thy light's flame with self-substantial fuel, Making a famine where abundance lies, Thy self thy foe, to thy sweet self too cruel: Thou that art now the world's fresh ornament, And only herald to the gaudy spring, Within thine own bud buriest thy content, And tender churl mak'st waste in niggarding: Pity the world, or else this glutton be, To eat the world's due, by the grave and thee. When forty winters shall besiege thy brow, And dig deep trenches in thy beauty's field, Thy youth's proud livery so gazed on now, Will be a tattered weed of small worth held: Then being asked, where all thy beauty lies, Where all the treasure of thy lusty days; To say within thine own deep sunken eyes, Were an all-eating shame, and thriftless praise.'''

# Save the original message to a file
with open("original_message.txt", "w", encoding="utf-8") as f:
    f.write(message)

# Define the password to use for encryption/decryption
password = "securepassword"

# Encrypt the file using OpenSSL AES-256 encryption
def openssl_encrypt(input_file, output_file, password):
    command = f"openssl enc -aes-256-cbc -salt -in {input_file} -out {output_file} -k {password} -pbkdf2"
    subprocess.run(command, shell=True)

# Decrypt the file using OpenSSL
def openssl_decrypt(input_file, output_file, password):
    command = f"openssl enc -aes-256-cbc -d -salt -in {input_file} -out {output_file} -k {password} -pbkdf2"
    subprocess.run(command, shell=True)

# Perform encryption and decryption
openssl_encrypt("original_message.txt", "encrypted_message.txt", password)
openssl_decrypt("encrypted_message.txt", "decrypted_message.txt", password)

# Compare the original and decrypted files
with open("original_message.txt", "r", encoding="utf-8") as f1, open("decrypted_message.txt", "r", encoding="utf-8") as f2:
    original_text = f1.read()
    decrypted_text = f2.read()

# Display results and comparison
print("Original Message:\n", original_text)
print("\nDecrypted Message:\n", decrypted_text)

if original_text == decrypted_text:
    print("\nSuccess: The decrypted message matches the original message.")
else:
    print("\nFailure: The decrypted message does not match the original message.")
