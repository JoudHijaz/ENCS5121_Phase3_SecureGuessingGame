# 🔐 ENCS5121 Phase 3 – Secure Online Guessing Game

This project is part of the final phase of the **ENCS5121 – Information Security and Computer Network Laboratory** course at Birzeit University. The application implements a secure client-server guessing game in Python, incorporating **RSA authentication**, **Diffie-Hellman key exchange**, and **AES-256-CBC encryption** for confidentiality, integrity, and mutual authentication.

---

## 📌 Objectives

- Implement RSA-based mutual authentication between client (Alice) and server (Bob)
- Perform Diffie-Hellman key exchange to derive a shared session key
- Use AES-256-CBC to encrypt all game data
- Prevent Man-in-the-Middle (MITM) attacks and achieve Perfect Forward Secrecy (PFS)
- Handle and detect failed authentication scenarios

---

## 🗂️ Project Structure

```
ENCS5121_Phase3_SecureGuessingGame/
│
├── client.py              # Alice (client) side implementation
├── server.py              # Bob (server) side implementation
├── gen_rsa.py             # Script to generate RSA keys
├── quick_prime_check.py   # Helper script to check primality
│
├── alice_priv.pem         # Alice's private RSA key
├── alice_pub.pem          # Alice's public RSA key
├── bob_priv.pem           # Bob's private RSA key
├── bob_pub.pem            # Bob's public RSA key
│
├── p_A.txt, q_A.txt       # Primes used to generate Alice’s RSA keys
├── p_B.txt, q_B.txt       # Primes used to generate Bob’s RSA keys
│
├── phase3_demo.mp4        # Demo video (optional for GitHub hosting)
├── README.md              # Project documentation and instructions

```

---

## 🧪 Test Cases Implemented

| Test Case        | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| ✅ Test Case 1    | Normal game flow: 2 complete rounds with successful mutual authentication. |
| ❌ Test Case 2    | Invalid Bob private key: Alice fails to authenticate Bob and terminates.   |
| ❌ Test Case 3    | Invalid Alice private key: Bob fails to authenticate Alice and terminates. |

---

## ⚙️ How to Run

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Server (Bob)

In one terminal or machine:

```bash
python server.py
```

### 3. Start the Client (Alice)

In another terminal or machine:

```bash
python client.py
```

---

## 🔐 Cryptographic Details

- **RSA Key Pairs**: 
  - Key size generated using primes > 310 digits
  - Public Key: `(N, e)` hardcoded
  - Private Key: `d` hardcoded (for lab simplicity)
  
- **Diffie-Hellman Key Exchange**:
  - MODP Group 14 (2048-bit prime)
  - Generator `g` and modulus `m` hardcoded
  - Exponents `a` and `b` are 2048-bit securely generated

- **Challenge-Response**:
  - `RA` and `RB` are 256-bit values
  - SHA-256 used to compute the `H` hash for authentication

- **Symmetric Encryption**:
  - AES-256-CBC for secure guessing game session
  - IV printed before encrypting/decrypting exchanged data

- **Security Features**:
  - Mutual Authentication
  - Forward Secrecy (exponents and session key destroyed post-session)
  - MITM attack protection via signature verification

---

## 📹 Demonstration Video

A full demonstration of the system and all test cases can be viewed here:

🎥 [**Click to watch demo video**](https://youtu.be/a6rvjh6adEw)



---

## 📎 Notes

- This implementation is for academic demonstration only.
- In real-world applications, keys should be securely stored, not hardcoded.
- Prime numbers used for RSA are stored in `.txt` files for transparency.
- Code uses `pycryptodome` for AES encryption and Python’s built-in crypto-safe random generation for keys and challenges.

---

## 📄 License

This repository is an academic submission for ENCS5121 – Term 1242 at Birzeit University. Not for commercial use.

---

