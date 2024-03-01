from pwn import *
import re
# Set the IP address and port
ip = "172.26.201.17"
port = 2131

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")
print(data1)

io.sendline(str(1))
data = io.recvline().decode("utf-8")
print(data)
x = data.split()
word = x[1][1:-1]
print(x)
print(word)
key = int(re.search(r'key=(\d+)', data).group(1))

print(key)
# ciphertext = "a" key = 1
def shift_decrypt(ciphertext, key):
    decrypted_text = ""
    for char in ciphertext: 
        decrypted_text = decrypted_text + chr((ord(char) - key - 97) % 26 + 97)
        # print(decrypted_text)
      
    return decrypted_text

ciphertext = shift_decrypt(word,key)

io.sendline(ciphertext)
# flag = io.recvline().decode().strip()
flag = io.recvline().decode("utf-8")
print(flag)

# Close the connection
io.close()