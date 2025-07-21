import re
from Crypto.Util.number import isPrime

# List your four prime‐candidate files here
filenames = ["p_A.txt", "q_A.txt", "p_B.txt", "q_B.txt"]

for fname in filenames:
    # Read and strip out any non-digit characters (spaces, newlines, etc.)
    with open(fname, 'r') as f:
        digits = re.sub(r"\D", "", f.read())
    n = int(digits)

    # Print results
    print(f"{fname}:")
    print(f"  Digits = {len(digits)}")              # Expect ≥ 310
    print(f"  Is prime? = {bool(isPrime(n))}\n")    # 1 → True (probable prime), 0 → False (composite)

