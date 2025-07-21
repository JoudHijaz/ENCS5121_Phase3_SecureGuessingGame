README.txt
==========

Phase 3: ENCS5121 Secure Guessing Game
--------------------------------------

This project hardens our number-guessing game by adding:
  • RSA mutual authentication using 310-digit primes  
  • Diffie–Hellman key exchange (2048-bit MODP Group 14)  
  • AES-256-CBC encryption of all game data  
  • Perfect forward secrecy & MITM resistance  

Prerequisites
-------------
  • Python 3.6+  
  • pycryptodome library  
    pip install pycryptodome  
  • Four text files, each with one ≥310-digit prime:  
      p_A.txt  
      q_A.txt  
      p_B.txt  
      q_B.txt  
  • Two terminals or VMs able to communicate on TCP port 5000  

File Overview
-------------
  gen_rsa.py      — reads p_*.txt & q_*.txt, generates RSA keypairs  
  p_A.txt…q_B.txt — your four chosen primes  
  alice_pub.pem   — Alice’s public key (N_A, e)  
  alice_priv.pem  — Alice’s private key (N_A, d)  
  bob_pub.pem     — Bob’s public key (N_B, e)  
  bob_priv.pem    — Bob’s private key (N_B, d)  
  server.py       — Bob’s app: RSA auth → DH → AES-CBC guessing game  
  client.py       — Alice’s app: RSA auth → DH → AES-CBC guessing game  
  video.mkv       — recorded demo of Test Cases 1–3  

1. Key Generation
-----------------
1. Place p_A.txt, q_A.txt, p_B.txt, q_B.txt in the project directory.  
2. Run:
   python3 gen_rsa.py  
3. Confirm you see for **each** side:
   [DEBUG] p = <prime>  
   [DEBUG] q = <prime>  
   [DEBUG] N = <p·q>  
   [DEBUG] e = 65537  
   [DEBUG] d = <computed>  
   [DEBUG] e·d mod φ = 1 ✓  
4. Output files:
   alice_pub.pem   alice_priv.pem  
   bob_pub.pem     bob_priv.pem  

2. Starting the Server (Bob)
----------------------------
In Terminal A:
  python3 server.py --host 0.0.0.0 --port 5000  

Expected:
  [DEBUG] server sees Alice’s N_A = …  
  [DEBUG] server sees Alice’s E_A = 65537  
  [Server] Listening on 0.0.0.0:5000  

Runtime debug shows:
  • Verifying Alice’s signature on A, RA  
  • Generating & signing B, RB  
  • Deriving session key K  
  • Logging each AES-CBC IV  

3. Starting the Client (Alice)
------------------------------
In Terminal B:
  python3 client.py --host <server_ip> --port 5000  

Expected:
  [DEBUG] client sees Alice’s N_A = …  
  [DEBUG] client sees Alice’s D_A = …  
  [Client] Connected to <server_ip>:5000  

Runtime debug shows:
  • Generating & signing A, RA  
  • Verifying Bob’s signature on B, RB  
  • Deriving session key K  
  • Logging each AES-CBC IV  

4. Test Case 1: Normal Round
----------------------------
1. Client chooses **1) Play**  
2. Guess until **“correct”**, repeat twice.  
3. Capture (before destruction):
   – Alice: a, RA, A  
   – Bob:   b, RB, B  
   – Session key K  
   – All printed AES IVs  
   – Confirmation messages:
     [Client] Bob authenticated.  
     [Server] Alice authenticated.  

5. Test Case 2: Fake Bob
------------------------
1. Edit **bob_priv.pem**, alter one digit of d_B.  
2. Restart server & client; client chooses **1) Play**.  
3. Client shows:
   [Client] Failed to authenticate Bob.  
   Authentication failed. Terminating session.  

6. Test Case 3: Fake Alice
--------------------------
1. Restore bob_priv.pem; edit **alice_priv.pem**, alter one digit of d_A.  
2. Restart server & client; client chooses **1) Play**.  
3. Server shows:
   [Server] Failed to authenticate Alice.  
   [Server] Authentication failed. Closing connection.  


