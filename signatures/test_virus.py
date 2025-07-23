# test_virus.py
import hashlib
with open("test_virus.py", "rb") as f:
    print(hashlib.sha256(f.read()).hexdigest())
VIRUS_SIGNATURE = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
print("This is a harmless test virus")