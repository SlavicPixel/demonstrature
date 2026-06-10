from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import padding as aes_padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.exceptions import InvalidSignature

import os
import socket
import time

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

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    
    with conn:
        print(f"Connected by {addr}")
        rsa_pem_client = conn.recv(2048)
        print(f"RSA PEM klijenta: {rsa_pem_client.decode()}")
        conn.sendall(public_key_pem)

        client_aes = conn.recv(2048)
        client_aes = private_key.decrypt(
            client_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"AES kljuc klijenta: {client_aes}")

        h = hmac.HMAC(client_aes, hashes.MD5())
        h_provjera = hmac.HMAC(client_aes, hashes.MD5())   

        aes_poruka = aes_cbc_encrypt(b'AES kljuc primljen', client_aes)
        conn.sendall(aes_poruka)

        packet1 = conn.recv(2048)
        poruka1_hash, poruka1 = packet1.decode().split(':')
        poruka1_hash = bytes.fromhex(poruka1_hash)
        poruka1 = bytes.fromhex(poruka1)
        print(f"Poruka1 hash: {poruka1_hash}")
        h_provjera.update(poruka1)
        try:
            h_provjera.verify(poruka1_hash)
            print("HMAC provjera uspješna.")
        except InvalidSignature:
            print("Integritet narušen!")
        
        poruka1 = aes_cbc_decrypt(poruka1, client_aes)
        print(poruka1)

        # ===== ZADATAK 3: SHA-256 hash dekriptirane poruke (dodano) =====
        hash_hex = hashes.Hash(hashes.SHA256())
        hash_hex.update(poruka1)                 # hash nad dekriptiranom porukom
        poruka1_sha = hash_hex.finalize().hex()  # hex string
        hash_enc = aes_cbc_encrypt(poruka1_sha.encode(), client_aes)

        h_hash = hmac.HMAC(client_aes, hashes.SHA256())  # svjez HMAC objekt
        h_hash.update(hash_enc)
        hash_enc_hmac = h_hash.finalize()

        packet2 = hash_enc_hmac.hex() + ':' + hash_enc.hex()
        packet2 = packet2.encode()
        conn.sendall(packet2)
        # ===== KRAJ ZADATKA 3 =====

        poruka2 = aes_cbc_encrypt(b'Poruka primljena', client_aes)
        h.update(poruka2)
        poruka2_hash = h.finalize()
        packet3 = poruka2_hash.hex() + ':' + poruka2.hex()
        packet3 = packet3.encode()
        conn.sendall(packet3)