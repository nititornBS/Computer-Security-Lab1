from pwn import *
import re
# Set the IP address and port
ip = "172.26.201.17"
port = 2131

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")
print(data1)

io.sendline(str(2))
for x in range(0, 9):
    data = io.recvline().decode("utf-8")
print(data)

def shift_encrypt(ciphertext, key):
    return  chr(((ord(ciphertext)-97)+ (ord(key)-97)) % 26 + 97)

data = data.split('"')
print(data)
pt = data[1]
key = data[3]
print("pain text : "+pt)
print("Key :"+key)

pt_arr = [*pt]
key_arr = [*key]

print(pt_arr)
number_char = len(pt_arr)
print(number_char)
encrypted_text = ""

for x in range(0, number_char):
    encrypted_text = encrypted_text + shift_encrypt(pt_arr[x],key_arr[x])
    
print("decrypted text is ::: "+encrypted_text)
io.sendline(encrypted_text)
flag = io.recvline().decode("utf-8")
print(flag)
io.close()