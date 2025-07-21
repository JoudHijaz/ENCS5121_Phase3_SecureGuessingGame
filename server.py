#!/usr/bin/env python3
"""
server.py — Phase 3 (Bob)
RSA mutual-authentication, Diffie-Hellman, AES-256-CBC guessing game
"""

import argparse, json, random, secrets, socket, struct
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


# After
N_B, D_B = load_keypair("bob_priv.pem")
N_A, E_A = load_keypair("alice_pub.pem")


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
# 3. DH parameters (Group 14)
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
# 4. AES helpers
# ──────────────────────────────────────
def aes_encrypt(pt, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(pt
    , AES.block_size))
    print(f"[Bob]   IV used = {iv.hex()}")

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
# 6. Mutual auth (Bob)
# ──────────────────────────────────────
def mutual_authenticate(conn):
    # Step 1: Receive A, RA, SA
    msg1 = recv_json(conn)
    A = int(msg1["A"])
    RA = bytes.fromhex(msg1["RA"])
    S_A = int(msg1["SA"])

    print(f"[Server] Received A: {A}")
    print(f"[Server] RA (challenge): {RA.hex()}")

    A_bytes = A.to_bytes(LEN_P, 'big')
    H1_int = int.from_bytes(sha256(b"Alice|Bob|" + A_bytes + RA).digest(), 'big')
    # right before: if modexp(S_A, E_A, N_A) != H1_int:
    print("[DEBUG] H1_int      =", H1_int)
    print("[DEBUG] recover(H1) =", modexp(S_A, E_A, N_A))

    if modexp(S_A, E_A, N_A) != H1_int:
        print("[Server] Failed to authenticate Alice.")
        send_json(conn, {"status": "FAIL"})
        return None

    print("[Server] Alice authenticated.")

    # Step 2: Send B, RB, SB
    b = secrets.randbits(2048)
    RB = secrets.token_bytes(32)
    B = modexp(g, b, p)

    print(f"[Bob]   b = {b}")
    print(f"[Bob]   RB = {RB.hex()}")
    print(f"[Bob]   B  = {B}")
    
    H2 = sha256(b"Bob|Alice|" + B.to_bytes(LEN_P, 'big') + RB).digest()
    S_B = modexp(int.from_bytes(H2, 'big'), D_B, N_B)


    send_json(conn, {"B": str(B), "RB": RB.hex(), "SB": str(S_B)})

    # Step 3: Receive SA2
    msg3 = recv_json(conn)
    S_A2 = int(msg3["SA2"])
    H3_int = int.from_bytes(sha256(b"Alice|Bob|" + B.to_bytes(LEN_P, 'big') + RA).digest(), 'big')
    
    if modexp(S_A2, E_A, N_A) != H3_int:
        print("[Server] Failed to validate Alice in Step 3.")
        send_json(conn, {"status": "FAIL"})
        return None

    send_json(conn, {"status": "OK"})

    # Session key
    shared = modexp(A, b, p)
    K = sha256(shared.to_bytes(LEN_P, 'big')).digest()
    print(f"[Bob] Shared session key K = {K.hex()}")

    return K

# ──────────────────────────────────────
# 7. Game logic & server loop
# ──────────────────────────────────────
def play_round(conn, K):
    secret = random.randint(1, 100)
    print(f"[Server] Secret number: {secret}")
    while True:
        pkt = conn.recv(4096)
        if not pkt: return False
        guess = int(aes_decrypt(pkt, K).decode())
        print(f"[Server] Client guessed: {guess}")
        if guess < secret:
            conn.sendall(aes_encrypt(b"higher", K))
        elif guess > secret:
            conn.sendall(aes_encrypt(b"lower", K))
        else:
            conn.sendall(aes_encrypt(b"correct", K))
            return True

def handle_client(conn, addr):
    print(f"[Server] Connection from {addr}")
    while True:
        K = mutual_authenticate(conn)
        if not K:
            print("[Server] Authentication failed. Closing connection.")
            break

        enc = conn.recv(4096)
        menu = aes_decrypt(enc, K).decode()
        if menu == "1":
            if not play_round(conn, K):
                break
        else:
            break
    conn.close()
    print("[Server] Connection closed.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    srv = socket.socket()
    srv.bind((args.host, args.port))
    srv.listen(1)
    print(f"[Server] Listening on {args.host}:{args.port}")
    while True:
        conn, addr = srv.accept()
        handle_client(conn, addr)

if __name__ == "__main__":
    main()

