### Solution for NoLeaks challenge in cryptohack.
### https://cryptohack.org/challenges/misc/

import base64
import codecs
from pwn import *
import json
import time
import hashlib
import base64

conn = remote('socket.cryptohack.org', 13370)
conn.recvline()

jsonPayload = '{"msg": "request"}'


sets = [set() for _ in range(20)]

val = 32640

done = False
while not done:
	conn.send(jsonPayload)
	resp = json.loads(conn.recvline())
	if 'ciphertext' in resp:
		for i in range(20):
			data = base64.b64decode(resp['ciphertext'])
			sets[i].add(data[i])

	done = True
	for i in range(20):
		if len(sets[i]) != 255:
			done = False
		else:
			print(val - sum(sets[i]))
	
	print(",".join([str(len(a)) for a in sets]))

for i in range(20):
	print(val - sum(sets[i]))
