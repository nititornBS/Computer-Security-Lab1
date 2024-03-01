#Owner Nititorn Boonsat 6530613010
from pwn import *
import re

ip = "172.26.201.17"
port = 2131

flag_q1 = ""
flag_q2 = ""
flag_q3 = ""
flag_q4 = ""

io = remote(ip, port)


# _____________________________________  Q1  ______________________________________________
#Owner Nititorn Boonsat 6530613010
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

def shift_decrypt(ciphertext, key):
    decrypted_text = ""
    for char in ciphertext: 
        decrypted_text = decrypted_text + chr((ord(char) - key - 97) % 26 + 97)
   
      
    return decrypted_text

ciphertext = shift_decrypt(word,key)

io.sendline(ciphertext)

flag = io.recvline().decode("utf-8")
print(flag)
flag_q1 = flag.split(":")[1][1:]



# _____________________________________  Q2  ______________________________________________

#Owner Nititorn Boonsat 6530613010
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
flag_q2 = flag.split(":")[1][1:]



# _____________________________________  Q3  ______________________________________________
#Owner Nititorn Boonsat 6530613010

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


def find_word(ciphertext, key):
    decrypted_text = ""
    for char in ciphertext: 
       
        decrypted_text = decrypted_text + chr((ord(char) - key - 97) % 26 + 97)
      
    return decrypted_text
for x in range(0,26):
    P_text = ""
    M_text = ""
    for u in range(0,len(hint)):
        P_text = find_word(hint,x)
        M_text = find_word(hint, -x)
    # print(P_text)
    temp_P_text = decript_text.find(P_text)
    # print(temp_P_text)

    # print(M_text)
    temp_M_text = decript_text.find(M_text)
    # print(temp_M_text)
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
flag_q3 = flag.split(":")[1][1:]





# _____________________________________  Q4  ______________________________________________
#Owner Nititorn Boonsat 6530613010

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

# Convert the decrypted bytes to a string



io.sendline(decrypted_bytes)
# flag = io.recvline().decode().strip()
flag = io.recvline().decode("utf-8")
print("flag of Q4 is ")
print(flag)
flag_q4= flag[1:]

print("flag of Q1 is "+flag_q1)
print("flag of Q2 is "+flag_q2)
print("flag of Q3 is "+flag_q3)
print("flag of Q4 is "+flag_q4)

io.close()