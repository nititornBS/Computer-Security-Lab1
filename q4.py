from pwn import *
import re
# Set the IP address and port
ip = "172.26.201.17"
port = 2131

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")
print(data1)

io.sendline(str(4))
cipher_text = ""
OTP_text = ""
data = io.recvline().decode("utf-8")
data = io.recvline().decode("utf-8")
data = data.split(":")
cipher_text = data[1][1:]
print(data)
data = io.recvline().decode("utf-8")
data = data.split(":")
print(data)
OTP_text = data[1][1:]
print("OTP :  "+ OTP_text)
print("cipher_text :  "+cipher_text)

otp_bytes = bytes.fromhex(OTP_text)
ciphertext_bytes = bytes.fromhex(cipher_text)
# print("OTP_bytes : "+otp_bytes)
# print("ciphertext_bytes  : " + ciphertext_bytes)

decrypted_bytes = bytes([a ^ b for a, b in zip(ciphertext_bytes, otp_bytes)])
print(decrypted_bytes)
for a, b in zip(ciphertext_bytes, otp_bytes):
    print(a)
    print(b)
    print(" ")
# Convert the decrypted bytes to a string



io.sendline(decrypted_bytes)
# flag = io.recvline().decode().strip()
flag = io.recvline().decode("utf-8")
print(flag)
io.close()