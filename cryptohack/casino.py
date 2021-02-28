### Solution for Lo-Hi card game challenge in cryptohack.
### https://cryptohack.org/challenges/misc/

import base64
import codecs
from pwn import *
import json
import time
import hashlib
import base64

from Crypto.Util.number import *

# Assumption:
# 
# First few pseudo values would have 11 deals.
# 
# This solution almost always succeeds :)

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']
total = len(VALUES) * len(SUITS)


a_secret, b_secret, known = 0, 0, False
mod = 2 ** 61 - 1
num_deals = 11

numbers = []
pseudoRandoms = []
picks = []

conn = remote('socket.cryptohack.org', 13383)

def reconstruct(a):
  r = 0
  for x in a:
    r *= total
    r += x

  print("psedo-random value for the round:", r)

  return r

def coeffs(x):
  x1, x2, x3 = x[0], x[1], x[2]
  r = inverse((x2 - x1), mod)
  a = (r * (x3 - x2)) % mod

  b = (x2 - a * x1) % mod

  print("seeds", a, b)

  return a, b

# Contains numbers in other of order of pop.
def rebase(n, b=52):
  if n < b:
    return [n]
  else:
    return rebase(n//b, b) + [n % b]

# Main Loop
while True:
  # print new line
  print("")

  # It is known that a deal has 11 rounds.
  for ii in range(num_deals):
    resp = json.loads(conn.recvline())
    print(resp)

    if "hand" not in resp:
      exit()

    hand = resp['hand'].split(" ")

    val = VALUES.index(hand[0])
    deck = SUITS.index(hand[-1])

    numbers.append(val + 13 * deck)

    jsonPayload = ""

    if not known or ii + 1 >= len(picks):
      # Do a best guess.
      if val < 12 - val:
        jsonPayload = '{"choice": "h"}'
      else:
        jsonPayload = '{"choice": "l"}'
    else:
      # Use picks to get next value.
      if picks[ii + 1] < picks[ii]:
        jsonPayload = '{"choice": "l"}'
      else:
        jsonPayload = '{"choice": "h"}'

    conn.send(jsonPayload)

  # If secrets are not known, simply accumulate known pseudo values.
  if not known:
    pseudoRandoms.append(reconstruct(numbers[-11:]))

    # When you know 3 pseudo randoms, you can derive secret seeds.
    if len(pseudoRandoms) == 3:
      a_secret, b_secret = coeffs(pseudoRandoms)
      known = True
    else:
      continue

  # Use secrets to predict next picks.
  nextVal = (pseudoRandoms[-1] * a_secret + b_secret) % mod
  pseudoRandoms.append(nextVal)
  picks = rebase(nextVal)

  picks = [i % 13 for i in picks]
  print("\nNext picks should be:", picks)

  num_deals = len(picks)
