from pwn import *
import re
# Set the IP address and port
ip = 'localhost'
port = 5000

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")
print(data1)

io.sendline(str(5))
data = io.recvline().decode("utf-8")
ciphertext = io.recvline().decode("utf-8")
print("ciphertext is :")
print(ciphertext)
hints= io.recvline().decode("utf-8")
print(hints)
sp_hints = hints.split(",")
# print(sp_hints)
after_hints = hints.split()
# print(after_hints)
flag = after_hints[5][:-1]

after__hints = hints.split(":")
plaintext_set = after__hints[2]
print(plaintext_set)
plaintext_set = plaintext_set.split('"')[1] 
print("plaintext_set :  ") 
print(plaintext_set)

print(flag)
flag_bytes = [ord(char) for char in flag]
print(flag_bytes)
flag_bytes2 = bytes(flag_bytes)
print(flag_bytes2)
# flag_bytes2_decoded = flag_bytes2.decode()
# print(flag_bytes2_decoded)
# print(len(flag));

OTP = ( flag_bytes2* (len(ciphertext)//len(flag_bytes2)))
print("OTP is ")
print(OTP)
print("otp len is "  + str(len(OTP)))
print(str(len(ciphertext)))
ciphertext_bytes = bytes.fromhex(ciphertext)
# print("ciphertext_bytes")
# print(ciphertext_bytes)
decrypted_bytes = bytes([a ^ b for a, b in zip(ciphertext_bytes, OTP)])
for a, b in zip(ciphertext_bytes, OTP):
    print(b)
    print(a)
    print(a ^ b )

    print(" ")
print(decrypted_bytes)
# print(flag)
# flag = sp_hints
# plantext=""
# ciphertext_bytes = bytes.fromhex(ciphertext)
# print(ciphertext_bytes)


# otp = flag*int(len(pt)/len(flag)),
# byte_flag = 
# OTP = flag*(len())

# decrypted_bytes = bytes([a ^ b for a, b in zip(ciphertext_bytes, OTP)])
# Any character in plaintext is in the following set: "(1se2'wrCnpi)ua,v-ocD0EtTI.gbmdAf 7lhFy", 
# (4) I pulled plaintext from somewhere in https://www.computing.psu.ac.th/en/ domain.

io.close()