import sys
import random
import string
import os
import time
import argparse

def get_random_string():
    # With combination of lower and upper case
    length = random.randint(8, 15)
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    return result_str

def xor(data):
    key = get_random_string()
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x) # handle data being bytes not string
        output_str += chr(o(current) ^ ord(current_key))

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext, key

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path_to_bin", type=str, default="shellcode.bin", help="path to shellcode bin file")
    args = parser.parse_args()

    try:
        shellcode = open(args.path_to_bin, "rb").read()
    except Exception as e:
        print("Something went wrong with trying to read your bin file.")
        print(e)
        sys.exit(1)

    # Encrypt payload
    buf, key = xor(shellcode)

    # Replace 
    with open("template.h", "rt") as template:
        data = template.read()

        # Replace char arrays
        data = data.replace('unsigned char buf[] = { 0x00 };', 'unsigned char buf[] = ' + buf)
        data = data.replace('char key[] = "key"', 'char key[] = "' + key + '"')
        
        # Write into header file
        with open("header.h", "w+") as tempfile:
            tempfile.write(data)


if __name__ == "__main__":
    main()
