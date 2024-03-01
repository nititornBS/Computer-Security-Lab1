from pwn import *
import re
# Set the IP address and port
ip = "172.26.201.17"
port = 2131

io = remote(ip, port)

data1 = io.recvline().decode("utf-8")
print(data1)

io.sendline(str(3))

data = io.recvline().decode("utf-8")
print(data)
data = data.split(':')
print(data[-1][0:-1])
decript_text = data[-1][1:-1]
cipher_text =[*data[-1][1:-1]]
print(cipher_text)
ascii_text =[]
for x in range(0, len(cipher_text)):
    ascii_text.append(((ord(cipher_text[x])-97)%26))
print(ascii_text)
pt= ""
key = 0
temp = io.recvline().decode("utf-8")
print(temp.split())
temp = temp.split()[6][2:-2]
hint = temp


def shift_decrypt(ciphertext, key):
    decrypted_text = ""
    for char in ciphertext: 
       
        decrypted_text = decrypted_text + chr((ord(char) - key - 97) % 26 + 97)
      
    return decrypted_text
for x in range(0,26):
    P_text = ""
    M_text = ""
    for u in range(0,len(hint)):
        P_text = shift_decrypt(hint,x)
        M_text = shift_decrypt(hint, -x)
    print(P_text)
    temp_P_text = decript_text.find(P_text)
    print(temp_P_text)

    print(M_text)
    temp_M_text = decript_text.find(M_text)
    print(temp_M_text)
    if temp_P_text!= -1 :
        key = x
    if temp_M_text!= -1 :
        key = -x
print(key)
def shift_decrypttest(ciphertext, key):
    decrypted_text = ""
    for char in ciphertext: 
       
        decrypted_text = decrypted_text + chr((ord(char) + key - 97) % 26 + 97)

    return decrypted_text
texttt = shift_decrypttest(decript_text,key)
print(texttt)
io.sendline(texttt)

flag = io.recvline().decode("utf-8")
print(flag)



io.close()