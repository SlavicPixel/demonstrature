# SIKS Kolokvij — rješenja po zadacima

Svaki zadatak ima **cijeli** `client.py` i `server.py` koji rade samostalno do tog koraka.
Nove linije u odnosu na prethodni korak su unutar `# ─── NOVO (Zadatak X) ───` ... `# ─── kraj NOVO ───`.

**Kako pokrenuti:** prvo `python3 server.py`, pa u drugom terminalu `python3 client.py`.

**Napomene (usklađeno sa zadatkom iz PDF-a):**
- HMAC je **SHA-256** svugdje (Zadatak 2b to traži). Ako si negdje koristio MD5 — SHA-256 je drop-in zamjena, radi identično.
- AES ključ je **AES-256** → `os.urandom(32)` (Zadatak 1b).
- `SO_REUSEADDR` na serveru da se port odmah oslobodi između pokretanja.
- **Zašto `hmac.hex() + ":" + sifrat.hex()` u jednom `sendall`?** TCP je tok bajtova, ne poruke. Dva uzastopna `sendall`-a se znaju spojiti u jedan segment, pa `recv` pročita oboje odjednom. Ako sve spakiraš u jedan `sendall` (hex polja odvojena s `:`) i pročitaš jednim `recv` + `split(":")`, taj problem nestaje. Hex je bitan jer sirovi šifrat može sadržavati bajt `:` i pokvariti `split`.

---

## Zadatak 1a — Socket + razmjena RSA ključeva

### client.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import socket

HOST = "127.0.0.1"
PORT = 65432

# RSA par ključeva (2048 bita)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(public_key_pem)              # pošalji svoj javni ključ
    rsa_pem = s.recv(2048)                  # primi serverov javni ključ
    print(f"RSA PEM servera:\n{rsa_pem.decode()}")
```

### server.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import socket

HOST = "127.0.0.1"
PORT = 65432

# RSA par ključeva (2048 bita)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        rsa_pem_client = conn.recv(2048)    # primi klijentov javni ključ
        print(f"RSA PEM klijenta:\n{rsa_pem_client.decode()}")
        conn.sendall(public_key_pem)        # pošalji svoj javni ključ
```

---

## Zadatak 1b — Sigurna razmjena AES ključa

**Dodano:** AES-CBC pomoćne funkcije, generiranje AES-256 ključa, slanje ključa šifriranog RSA-om (OAEP/SHA-256), te potvrda "AES kljuc primljen" šifrirana AES-CBC.

### client.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

# ─── NOVO (1b): AES-CBC pomoćne funkcije ───
def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()      # IV + šifrat

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)
# ─── kraj NOVO (1b) ───

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

# ─── NOVO (1b): AES-256 ključ ───
aes_key = os.urandom(32)
# ─── kraj NOVO (1b) ───

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(public_key_pem)
    rsa_pem = s.recv(2048)
    print(f"RSA PEM servera:\n{rsa_pem.decode()}")

    # ─── NOVO (1b): šifriraj AES ključ serverovim RSA ključem (OAEP/SHA-256) i pošalji ───
    rsa_public_key_server = load_pem_public_key(rsa_pem)
    aes_key_enc = rsa_public_key_server.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    s.sendall(aes_key_enc)

    # primi i dekriptiraj potvrdu
    potvrda = aes_cbc_decrypt(s.recv(2048), aes_key)
    print(potvrda.decode())
    # ─── kraj NOVO (1b) ───
```

### server.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

# ─── NOVO (1b): AES-CBC pomoćne funkcije ───
def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)
# ─── kraj NOVO (1b) ───

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        rsa_pem_client = conn.recv(2048)
        print(f"RSA PEM klijenta:\n{rsa_pem_client.decode()}")
        conn.sendall(public_key_pem)

        # ─── NOVO (1b): dekriptiraj AES ključ privatnim ključem, ispiši hex, pošalji potvrdu ───
        aes_key_enc = conn.recv(2048)
        client_aes = private_key.decrypt(
            aes_key_enc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"AES ključ (hex): {client_aes.hex()}")

        potvrda = aes_cbc_encrypt(b"AES kljuc primljen", client_aes)
        conn.sendall(potvrda)
        # ─── kraj NOVO (1b) ───
```

---

## Zadatak 2a — Razmjena šifriranih poruka (bez HMAC-a)

**Dodano:** klijent šalje "Ovo je tajna poruka" (AES-CBC), server dekriptira, ispiše i odgovori "Poruka primljena". Ovdje je svaka strana pošalje točno jednu poruku po smjeru, pa je dovoljan običan `sendall`/`recv` — bez pakiranja.

### client.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

aes_key = os.urandom(32)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(public_key_pem)
    rsa_pem = s.recv(2048)
    print(f"RSA PEM servera:\n{rsa_pem.decode()}")

    rsa_public_key_server = load_pem_public_key(rsa_pem)
    aes_key_enc = rsa_public_key_server.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    s.sendall(aes_key_enc)

    potvrda = aes_cbc_decrypt(s.recv(2048), aes_key)
    print(potvrda.decode())

    # ─── NOVO (2a): šifrirana razmjena poruka ───
    poruka1 = aes_cbc_encrypt(b"Ovo je tajna poruka", aes_key)
    s.sendall(poruka1)

    odgovor = aes_cbc_decrypt(s.recv(2048), aes_key)
    print(odgovor.decode())
    # ─── kraj NOVO (2a) ───
```

### server.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        rsa_pem_client = conn.recv(2048)
        print(f"RSA PEM klijenta:\n{rsa_pem_client.decode()}")
        conn.sendall(public_key_pem)

        aes_key_enc = conn.recv(2048)
        client_aes = private_key.decrypt(
            aes_key_enc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"AES ključ (hex): {client_aes.hex()}")

        potvrda = aes_cbc_encrypt(b"AES kljuc primljen", client_aes)
        conn.sendall(potvrda)

        # ─── NOVO (2a): primi poruku, dekriptiraj, odgovori ───
        poruka1 = aes_cbc_decrypt(conn.recv(2048), client_aes)
        print(poruka1.decode())

        odgovor = aes_cbc_encrypt(b"Poruka primljena", client_aes)
        conn.sendall(odgovor)
        # ─── kraj NOVO (2a) ───
```

---

## Zadatak 2b — HMAC provjera integriteta

**Dodano / izmijenjeno:** uz svaku poruku ide HMAC (SHA-256) nad **šifratom**, s AES ključem kao HMAC ključem. Sve se šalje u **jednom paketu** `hmac_hex:sifrat_hex`. Primatelj prvo provjeri HMAC, pa tek onda dekriptira; ako ne odgovara → "Integritet narušen!" i prekida vezu. Dodani importi: `hmac`, `InvalidSignature`.

### client.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding, hmac      # ← hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature                          # ← InvalidSignature
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

aes_key = os.urandom(32)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(public_key_pem)
    rsa_pem = s.recv(2048)
    print(f"RSA PEM servera:\n{rsa_pem.decode()}")

    rsa_public_key_server = load_pem_public_key(rsa_pem)
    aes_key_enc = rsa_public_key_server.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    s.sendall(aes_key_enc)

    potvrda = aes_cbc_decrypt(s.recv(2048), aes_key)
    print(potvrda.decode())

    # ─── NOVO (2b): poruka1 + HMAC (SHA-256), sve u jednom paketu ───
    poruka1 = aes_cbc_encrypt(b"Ovo je tajna poruka", aes_key)
    h1 = hmac.HMAC(aes_key, hashes.SHA256())
    h1.update(poruka1)                                  # HMAC nad ŠIFRATOM
    paket1 = h1.finalize().hex() + ":" + poruka1.hex()  # hmac_hex : sifrat_hex
    s.sendall(paket1.encode())

    # primi odgovor (hmac_hex : sifrat_hex): prvo provjeri HMAC pa dekriptiraj
    paket = s.recv(2048).decode()
    odg_hmac_hex, odg_hex = paket.split(":")
    odg_hmac = bytes.fromhex(odg_hmac_hex)
    odgovor = bytes.fromhex(odg_hex)
    h2 = hmac.HMAC(aes_key, hashes.SHA256())
    h2.update(odgovor)
    try:
        h2.verify(odg_hmac)
        print("HMAC provjera uspješna.")
    except InvalidSignature:
        print("Integritet narušen!")
        exit()                                          # veza se prekida
    print(aes_cbc_decrypt(odgovor, aes_key).decode())
    # ─── kraj NOVO (2b) ───
```

### server.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding, hmac      # ← hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature                          # ← InvalidSignature
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        rsa_pem_client = conn.recv(2048)
        print(f"RSA PEM klijenta:\n{rsa_pem_client.decode()}")
        conn.sendall(public_key_pem)

        aes_key_enc = conn.recv(2048)
        client_aes = private_key.decrypt(
            aes_key_enc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"AES ključ (hex): {client_aes.hex()}")

        potvrda = aes_cbc_encrypt(b"AES kljuc primljen", client_aes)
        conn.sendall(potvrda)

        # ─── NOVO (2b): primi paket (hmac_hex : sifrat_hex), provjeri pa dekriptiraj ───
        paket = conn.recv(2048).decode()
        p1_hmac_hex, p1_hex = paket.split(":")
        p1_hmac = bytes.fromhex(p1_hmac_hex)
        poruka1 = bytes.fromhex(p1_hex)
        h1 = hmac.HMAC(client_aes, hashes.SHA256())
        h1.update(poruka1)
        try:
            h1.verify(p1_hmac)
            print("HMAC provjera uspješna.")
        except InvalidSignature:
            print("Integritet narušen!")
            exit()                                      # veza se prekida
        print(aes_cbc_decrypt(poruka1, client_aes).decode())

        # odgovor + HMAC u jednom paketu
        odgovor = aes_cbc_encrypt(b"Poruka primljena", client_aes)
        h2 = hmac.HMAC(client_aes, hashes.SHA256())
        h2.update(odgovor)
        paket_odg = h2.finalize().hex() + ":" + odgovor.hex()
        conn.sendall(paket_odg.encode())
        # ─── kraj NOVO (2b) ───
```

---

## Zadatak 3 — Funkcija `provjeri_integritet`

**Dodano:** funkcija `provjeri_integritet(poruka, hash_hex)` (na klijentu). Server nakon dekriptiranja poruke iz Zadatka 2 izračuna **SHA-256 hash dekriptirane poruke**, pošalje ga kao hex string (AES-CBC + HMAC), a klijent ga primi, dekriptira i pozove funkciju nad **originalnom** porukom.

> **Redoslijed poruka:** server sada šalje *prvo* paket s hashom, *pa* odgovor "Poruka primljena". Ta dva `sendall`-a razdvaja AES enkripcija odgovora između njih, što ih dovoljno odvoji na mreži. Ako bi se ikad spojili, spakiraj ih u jedan paket s više polja (`a:b:c:d`) na isti način.

### client.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)

# ─── NOVO (3): provjera integriteta SHA-256 ───
def provjeri_integritet(poruka, hash_hex):
    """Prima poruku (bytes) i hex string hasha. Vraća True ako se SHA-256 podudara."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(poruka)
    return digest.finalize().hex() == hash_hex
# ─── kraj NOVO (3) ───

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

aes_key = os.urandom(32)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(public_key_pem)
    rsa_pem = s.recv(2048)
    print(f"RSA PEM servera:\n{rsa_pem.decode()}")

    rsa_public_key_server = load_pem_public_key(rsa_pem)
    aes_key_enc = rsa_public_key_server.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    s.sendall(aes_key_enc)

    potvrda = aes_cbc_decrypt(s.recv(2048), aes_key)
    print(potvrda.decode())

    # poruka1 + HMAC (2b)
    poruka1 = aes_cbc_encrypt(b"Ovo je tajna poruka", aes_key)
    h1 = hmac.HMAC(aes_key, hashes.SHA256())
    h1.update(poruka1)
    paket1 = h1.finalize().hex() + ":" + poruka1.hex()
    s.sendall(paket1.encode())

    # ─── NOVO (3): primi SHA-256 hash poruke (hmac_hex : sifrat_hex), provjeri integritet ───
    paket = s.recv(2048).decode()
    hash_hmac_hex, hash_enc_hex = paket.split(":")
    hash_hmac = bytes.fromhex(hash_hmac_hex)
    hash_enc = bytes.fromhex(hash_enc_hex)
    h_hash = hmac.HMAC(aes_key, hashes.SHA256())
    h_hash.update(hash_enc)
    try:
        h_hash.verify(hash_hmac)
        print("HMAC provjera uspješna.")
    except InvalidSignature:
        print("Integritet narušen!")
        exit()
    primljeni_hash = aes_cbc_decrypt(hash_enc, aes_key).decode()
    rezultat = provjeri_integritet(b"Ovo je tajna poruka", primljeni_hash)
    print(f"Integritet poruke potvrđen: {rezultat}")
    # ─── kraj NOVO (3) ───

    # odgovor + HMAC (2b)
    paket = s.recv(2048).decode()
    odg_hmac_hex, odg_hex = paket.split(":")
    odg_hmac = bytes.fromhex(odg_hmac_hex)
    odgovor = bytes.fromhex(odg_hex)
    h2 = hmac.HMAC(aes_key, hashes.SHA256())
    h2.update(odgovor)
    try:
        h2.verify(odg_hmac)
        print("HMAC provjera uspješna.")
    except InvalidSignature:
        print("Integritet narušen!")
        exit()
    print(aes_cbc_decrypt(odgovor, aes_key).decode())
```

### server.py
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as aes_padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import socket

HOST = "127.0.0.1"
PORT = 65432

def add_pkcs7_padding(data, block_size=128):
    padder = aes_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def remove_pkcs7_padding(padded, block_size=128):
    unpadder = aes_padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padded = add_pkcs7_padding(plaintext, algorithms.AES.block_size)
    return iv + enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext[16:]) + dec.finalize()
    return remove_pkcs7_padding(padded, algorithms.AES.block_size)

# ─── NOVO (3): ista funkcija dostupna i na serveru (po želji) ───
def provjeri_integritet(poruka, hash_hex):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(poruka)
    return digest.finalize().hex() == hash_hex
# ─── kraj NOVO (3) ───

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        rsa_pem_client = conn.recv(2048)
        print(f"RSA PEM klijenta:\n{rsa_pem_client.decode()}")
        conn.sendall(public_key_pem)

        aes_key_enc = conn.recv(2048)
        client_aes = private_key.decrypt(
            aes_key_enc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"AES ključ (hex): {client_aes.hex()}")

        potvrda = aes_cbc_encrypt(b"AES kljuc primljen", client_aes)
        conn.sendall(potvrda)

        # primi poruka1 + HMAC (2b)
        paket = conn.recv(2048).decode()
        p1_hmac_hex, p1_hex = paket.split(":")
        p1_hmac = bytes.fromhex(p1_hmac_hex)
        poruka1 = bytes.fromhex(p1_hex)
        h1 = hmac.HMAC(client_aes, hashes.SHA256())
        h1.update(poruka1)
        try:
            h1.verify(p1_hmac)
            print("HMAC provjera uspješna.")
        except InvalidSignature:
            print("Integritet narušen!")
            exit()
        poruka1_plain = aes_cbc_decrypt(poruka1, client_aes)
        print(poruka1_plain.decode())

        # ─── NOVO (3): SHA-256 hash DEKRIPTIRANE poruke -> hex string, pošalji (hmac_hex : sifrat_hex) ───
        sha = hashes.Hash(hashes.SHA256())
        sha.update(poruka1_plain)
        poruka1_sha = sha.finalize().hex()
        hash_enc = aes_cbc_encrypt(poruka1_sha.encode(), client_aes)
        h_hash = hmac.HMAC(client_aes, hashes.SHA256())
        h_hash.update(hash_enc)
        paket_hash = h_hash.finalize().hex() + ":" + hash_enc.hex()
        conn.sendall(paket_hash.encode())
        # ─── kraj NOVO (3) ───

        # odgovor + HMAC (2b)
        odgovor = aes_cbc_encrypt(b"Poruka primljena", client_aes)
        h2 = hmac.HMAC(client_aes, hashes.SHA256())
        h2.update(odgovor)
        paket_odg = h2.finalize().hex() + ":" + odgovor.hex()
        conn.sendall(paket_odg.encode())
```

### Očekivani ispis (klijent, sve radi)
```
RSA PEM servera:
-----BEGIN RSA PUBLIC KEY-----
...
-----END RSA PUBLIC KEY-----
AES kljuc primljen
HMAC provjera uspješna.
Integritet poruke potvrđen: True
HMAC provjera uspješna.
Poruka primljena
```
