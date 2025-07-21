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
