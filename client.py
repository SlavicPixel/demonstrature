from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import padding as aes_padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

from cryptography.exceptions import InvalidSignature

import os
import socket

def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def remove_pkcs7_padding(padded_data, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def aes_cbc_encrypt(plaintext, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padded_data = add_pkcs7_padding(plaintext, block_size=algorithms.AES.block_size)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_cbc_decrypt(ciphertext, key):
    backend = default_backend()
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    plaintext = remove_pkcs7_padding(padded_plaintext, block_size=algorithms.AES.block_size)
    return plaintext

def provjeri_integritet(poruka, hash_hex):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(poruka)
    izracunati_hash = digest.finalize()
    return izracunati_hash.hex() == hash_hex

HOST = "127.0.0.1" 
PORT = 65432

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'1234')
)

public_key = private_key.public_key()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1
)

aes_key = os.urandom(16)
h = hmac.HMAC(aes_key, hashes.MD5())
h_provjera = hmac.HMAC(aes_key, hashes.MD5())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(public_key_pem)

    rsa_pem = s.recv(2048)
    print(f"RSA PEM servera: {rsa_pem.decode()}")

    rsa_public_key_server = load_pem_public_key(rsa_pem)

    ciphertext = rsa_public_key_server.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    s.sendall(ciphertext)

    aes_poruka = aes_cbc_decrypt(s.recv(2048), aes_key)
    print(aes_poruka)

    poruka1 = aes_cbc_encrypt(b'Ovo je tajna poruka', aes_key)
    h.update(poruka1)
    poruka1_hash = h.finalize()
    print(f"Poruka1 hash: {poruka1_hash}")
    packet1 = poruka1_hash.hex() + ':' + poruka1.hex()
    packet1 = packet1.encode()
    s.sendall(packet1)

    # ===== ZADATAK 3: primi hash, provjeri HMAC pa integritet (dodano) =====
    packet2 = s.recv(2048)
    hash_hmac, hash_enc = packet2.decode().split(':')
    hash_hmac = bytes.fromhex(hash_hmac)
    hash_enc = bytes.fromhex(hash_enc)

    h_hash_provjera = hmac.HMAC(aes_key, hashes.SHA256())  # svjez HMAC objekt
    h_hash_provjera.update(hash_enc)
    try:
        h_hash_provjera.verify(hash_hmac)
        print("HMAC provjera uspješna. 1")
    except InvalidSignature:
        print("Integritet narušen! 1")

    primljeni_hash = aes_cbc_decrypt(hash_enc, aes_key).decode()
    rezultat = provjeri_integritet(b'Ovo je tajna poruka', primljeni_hash)
    print(f"Integritet poruke potvrđen: {rezultat}")
    # ===== KRAJ ZADATKA 3 =====

    packet3 = s.recv(2048)
    poruka2_hash, poruka2 = packet3.decode().split(':')
    poruka2_hash = bytes.fromhex(poruka2_hash)
    poruka2 = bytes.fromhex(poruka2)
    h_provjera.update(poruka2)
    try:
        h_provjera.verify(poruka2_hash)
        print("HMAC provjera uspješna. 2")
    except InvalidSignature:
        print("Integritet narušen! 2")
    poruka2 = aes_cbc_decrypt(poruka2, aes_key) 
    print(poruka2)