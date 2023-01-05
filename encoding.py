import argparse
import sys
import base64
import colorama

colorama.init()
red = '\033[31m'
yellow = '\033[93m'
green = '\033[92m'


parser = argparse.ArgumentParser(description="Decodes base64 and base32 cypher...", usage="%(prog)s --b64/--b32 cypher", epilog="%(prog)s --b64 aGVsbG8=")
parser.add_argument("--b64", help="Decodes base64", metavar="Base 64", dest="b64", nargs="+")
parser.add_argument("--b32", help="Decodes base32", metavar="Base 32", dest="b32", nargs="+")
parser.add_argument("--e64", help="Encodes to base64", metavar=" Encodes Base 64", dest="e64", nargs="+")
parser.add_argument("--e32", help="Encodes to base32", metavar="Encodes Base 32", dest="e32", nargs="+")
parser.add_argument("--bin", help="Converting to binary", metavar="Binary", dest="bin", nargs="+")
parser.add_argument("-v", help="Prints version", action="version", version="%(prog)s 1.0")

args = parser.parse_args()
if len(sys.argv) == 1:
	parser.print_help(sys.stderr)
	sys.exit()

b64 = args.b64
b32 = args.b32
e64 = args.e64
e32 = args.e32
binary = args.bin

if b64:
    print(red,"[+]                       Decoding base 64 ...\n")
    for i in b64:
	    print(yellow, f"[{b64.index(i) + 1}] {i}          {(base64.b64decode(i)).decode()}")

if b32:
    print(red,"[+]                       Decoding base 32 ...\n")
    for i in b32:
	    print(yellow, f"[{b32.index(i) + 1}] {i}          {(base64.b32decode(i)).decode()}")

if e64:
    print(green,"[+]                       Encoding to base 64\n")
    for i in e64:
        message_bytes = i.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print(yellow, f"[{e64.index(i) + 1}] {i}          {base64_message}")

if e32:
    print(green,"[+]                       Encoding to base 32\n")
    for i in e32:
        message_bytes = i.encode('ascii')
        base32_bytes = base64.b32encode(message_bytes)
        base32_message = base32_bytes.decode('ascii')
        print(yellow, f"[{e32.index(i) + 1}] {i}           {base32_message}")

if binary:
    print(green, "[+]                      Converting to binary\n")
    for i in binary:
        print(yellow, f"[{binary.index(i) + 1}] {i}         {bin(int(i))[2:]}")


