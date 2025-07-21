# gen_rsa.py — Manual RSA key generation using saved primes, with sanity checks

from Crypto.Util.number import inverse
from math import gcd

# === Helper Functions ===
def read_prime(filename):
    with open(filename, 'r') as f:
        return int(f.read().strip())

def make_keys(p, q, e=65537):
    # Compute modulus and phi
    N = p * q
    phi = (p - 1) * (q - 1)

    # Debug output
    print(f"[DEBUG] p = {p}")
    print(f"[DEBUG] q = {q}")
    print(f"[DEBUG] N = {N}")
    
    # Check that e is coprime to phi
    if gcd(e, phi) != 1:
        raise ValueError("e not coprime to φ; choose another e")

    # Compute d and assert correctness
    d = inverse(e, phi)
    assert (e * d) % phi == 1, "Assertion failed: d is not inverse of e mod φ"
    print(f"[DEBUG] e = {e}")
    print(f"[DEBUG] d = {d}")
    print("[DEBUG] e·d mod φ = 1 ✓")

    return N, e, d

def write_keypair(name, N, e, d):
    with open(f"{name}_pub.pem", "w") as f:
        f.write(f"{N}\n{e}")
    with open(f"{name}_priv.pem", "w") as f:
        f.write(f"{N}\n{d}")

# === Load primes ===
p_A = read_prime("p_A.txt")
q_A = read_prime("q_A.txt")
p_B = read_prime("p_B.txt")
q_B = read_prime("q_B.txt")

# === Generate Keys ===
e = 65537  # Common public exponent

# Alice
print("\nGenerating Alice's keypair...")
N_A, e_A, d_A = make_keys(p_A, q_A, e)
write_keypair("alice", N_A, e_A, d_A)
print("[✔] Alice keypair written to alice_pub.pem and alice_priv.pem\n")

# Bob
print("Generating Bob's keypair...")
N_B, e_B, d_B = make_keys(p_B, q_B, e)
write_keypair("bob", N_B, e_B, d_B)
print("[✔] Bob keypair written to bob_pub.pem and bob_priv.pem")

