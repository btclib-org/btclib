#!/usr/bin/python3

import hashlib
import time

msg = input('insert string: ')
if msg == "": msg = "Hello, world!"

zeros = input('n of zeros: ')
if zeros == "": zeros = 5
else          : zeros = int(zeros)
assert (zeros > 0), "the number of zeros to look for must be greater than zero"

print("\nstring is:", msg)
print("looking for", zeros, "zeros")

start = time.clock()

# n[i] is used to count the results starting with i+1 zeros
n = [0 for x in range(zeros)]
maxEval = pow(16,zeros+1)
i = 0
while (n[zeros-1] == 0 and i < maxEval):
  string = msg+str(i)
  hashValue = hashlib.sha256(string.encode()).hexdigest()
  for j in range (0, zeros):
    if hashValue[j] != "0":
      break
    n[j] += 1
    if n[zeros-1] == 1: nonce = i
  i += 1
    
elapsed = round(time.clock() - start)

print("\nperformed evaluations:", i, "/", maxEval)
print("elapsed time         :", elapsed, "seconds")
print("zeros found:", n)

if (n[zeros-1] == 1):
  print("nonce      :", nonce)
  string = msg+str(nonce)
  print(string)
  print(hashlib.sha256(string.encode()).hexdigest())
else:
  print("nonce not found")
