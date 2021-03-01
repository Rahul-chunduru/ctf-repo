### Solution for MD0 challenge in cryptohack.
### https://cryptohack.org/challenges/misc/

import base64
from pwn import *
import os
import json


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def bxor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


# compressFunc with both iv, data in byteArray.
def compressFunc(iv, data):
  out = iv
  for i in range(0, len(data), 16):
    blk = data[i:i+16]
    out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    print(len(out), "interim")
  return out

# Connect to challenge.
conn = remote('socket.cryptohack.org', 13388)
print(conn.recvline())

# obtain hash for empty string i.e, pad(key, 16)
data1 = pad(os.urandom(16), 16)
jsonPayload = '{"option":"sign","message":""}'
conn.send(jsonPayload)

resp = json.loads(conn.recvline())
sign = bytes.fromhex(resp["signature"])
print("send data", data1.hex())
print("got sign", sign)


# send to have MD hash for "message" = padding + "admin=True"
send_msg = data1[16:] + b"admin=True"
forged_msg = send_msg.hex()

# Compute hash using the sign received.
tot_msg = pad(data1 + b"admin=True", 16)
forged_sign = compressFunc(sign, tot_msg[32:]).hex()

# Send json data.
jsonPayload = {"option" : "get_flag", "signature": forged_sign, "message": forged_msg}
print(json.dumps(jsonPayload))
conn.send(json.dumps(jsonPayload))

# receive data.
print(conn.recvline())
