#!/usr/bin/env python3
"""
client.py — Phase 3 (Alice)
RSA mutual-authentication, Diffie-Hellman key exchange,
AES-256-CBC encrypted guessing game
"""

import argparse, json, secrets, socket, struct
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ──────────────────────────────────────
# 1. Load RSA keys from file
# ──────────────────────────────────────
def load_keypair(path):
    with open(path) as f:
        lines = f.readlines()
        N = int(lines[0].strip())
        val = int(lines[1].strip())
    return N, val


N_A, D_A = load_keypair("alice_priv.pem")
N_B, E_B = load_keypair("bob_pub.pem")
print(f"[DEBUG] client sees Alice’s N_A = {N_A}")
print(f"[DEBUG] client sees Alice’s D_A = {D_A}")

# ──────────────────────────────────────
# 2. Fast modular exponentiation
# ──────────────────────────────────────
def modexp(base, exp, mod):
    res = 1
    base %= mod
    while exp:
        if exp & 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return res

# ──────────────────────────────────────
# 3. DH Group 14 parameters
# ──────────────────────────────────────
g = 2
p = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4836"
    "1C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2"
    "EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
LEN_P = (p.bit_length() + 7) // 8

# ──────────────────────────────────────
# 4. AES-CBC helpers
# ──────────────────────────────────────
def aes_encrypt(pt, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(pt, AES.block_size))
    print(f"[Alice] IV used = {iv.hex()}")
    return iv + ct

def aes_decrypt(pkt, key):
    iv, ct = pkt[:16], pkt[16:]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)

# ──────────────────────────────────────
# 5. JSON framing
# ──────────────────────────────────────
def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Peer closed early")
        buf += chunk
    return buf

def recv_json(sock):
    raw = recv_all(sock, 4)
    length, = struct.unpack("!I", raw)
    return json.loads(recv_all(sock, length).decode())

# ──────────────────────────────────────
# 6. Mutual authentication (Alice)
# ──────────────────────────────────────
def mutual_auth(sock):
    # Step 1: Alice → Bob
    a = secrets.randbits(2048)
    RA = secrets.token_bytes(32)
    A = modexp(g, a, p)
    # Step 1: Alice → Bob
    a = secrets.randbits(2048)
    RA = secrets.token_bytes(32)
    A  = modexp(g, a, p)
    print(f"[Alice] a = {a}")
    print(f"[Alice] RA = {RA.hex()}")
    print(f"[Alice] A  = {A}")


    H1 = sha256(b"Alice|Bob|" + A.to_bytes(LEN_P, 'big') + RA).digest()
    H1_int = int.from_bytes(H1, 'big')
    S_A = modexp(H1_int, D_A, N_A)
    send_json(sock, {"A": str(A), "RA": RA.hex(), "SA": str(S_A)})
# client.py, inside mutual_auth() after S_A = …
    print(f"[Client DEBUG] H1_int = {H1_int}")
    print(f"[Client DEBUG] S_A (signed H1) = {S_A}")

    # Step 2: Bob → Alice
    msg2 = recv_json(sock)
    if "status" in msg2:
        return None
    B = int(msg2["B"])
    RB = bytes.fromhex(msg2["RB"])
    S_B = int(msg2["SB"])

    print(f"[Client] B: {B}")
    print(f"[Client] RB (challenge): {RB.hex()}")

    H2 = sha256(b"Bob|Alice|" + B.to_bytes(LEN_P, 'big') + RB).digest()
    H2_int = int.from_bytes(H2, 'big')
    

    if modexp(S_B, E_B, N_B) != H2_int:
        print("[Client] Failed to authenticate Bob.")
        return None
    print("[Client] Bob authenticated.")

    # Step 3: Alice → Bob
    H3 = sha256(b"Alice|Bob|" + B.to_bytes(LEN_P, 'big') + RA).digest()
    H3_int = int.from_bytes(H3, 'big')
    S_A2 = modexp(H3_int, D_A, N_A)
    send_json(sock, {"SA2": str(S_A2)})

    # Final check
    status = recv_json(sock).get("status")
    if status != "OK":
        print("[Client] Failed to complete mutual authentication.")
        return None
    print("[Client] Alice authenticated.")

    # Session key K
    S_shared = modexp(B, a, p)
    K = sha256(S_shared.to_bytes(LEN_P, 'big')).digest()
    print(f"[Alice] Derived session key K = {K.hex()}")
    return K

# ──────────────────────────────────────
# 7. Main client loop
# ──────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port))
    print(f"[Client] Connected to {args.host}:{args.port}")

    while True:
        K = mutual_auth(sock)
        if not K:
            print("Authentication failed. Terminating session.")
            break

        choice = input("1) Play  2) Exit > ").strip()
        sock.sendall(aes_encrypt(choice.encode(), K))
        if choice != '1':
            break

        while True:
            guess = input("Guess 1-100: ").strip()
            sock.sendall(aes_encrypt(guess.encode(), K))
            resp = aes_decrypt(sock.recv(4096), K).decode()
            print(resp)
            if resp == 'correct':
                break

    sock.close()

if __name__ == "__main__":
    main()

