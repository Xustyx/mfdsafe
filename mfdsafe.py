#!/usr/bin/env python

import codecs
import sys


C3 = [False,True,True]
C3T = [False,False,True]

SECTOR_SIZE = 64
ACCESS_BITS_OFFSET = 54
ACCESS_BITS_SIZE = 3


if len(sys.argv) == 1:
	sys.exit(
'''
Usage: mfdsafe.py ./dump.mfd
Mifare safe acces bits dumps.
'''
)


def set_bit(v, index, x):
	if x:
		return apply_bit(v,index)
	return clear_bit(v,index)


def apply_bit(value, bit):
	return value | (1<<bit)


def clear_bit(value, bit):
	return value & ~(1<<bit)


def access_bits_to_str(access_bits):
	access_bits_str = codecs.encode(access_bits, 'hex')

	if not isinstance(access_bits_str, str):
		access_bits_str = str(access_bits_str,'ascii')
		
	return access_bits_str


def new_access_bits(access_bits):
	new_access_bits = []

	new_access_bits.append(set_bit(map(ord, access_bits)[0], 7, not C3[1]))
	new_access_bits[0] = set_bit(new_access_bits[0], 3, not C3[0])

	new_access_bits.append(set_bit(map(ord, access_bits)[1], 7, C3[0]))
	new_access_bits[1] = set_bit(new_access_bits[1], 3, not C3[2])

	new_access_bits.append(set_bit(map(ord, access_bits)[2], 7, C3[2]))
	new_access_bits[2] = set_bit(new_access_bits[2], 3, C3[1])

	return new_access_bits


def set_access_bits(data):
	bytez = bytearray(data)
	
	for i in range(0, 16):
		start = i * SECTOR_SIZE + ACCESS_BITS_OFFSET
		end = start + ACCESS_BITS_SIZE
		
		print bytez[start]
		
		access_bits = data[start:end]
		
		access_bits_str = access_bits_to_str(access_bits)
		print("Access bits     (%d): %s" % (i, access_bits_str))
		
		replace_access_bits = new_access_bits(access_bits)
		
		replace_access_bits_str = access_bits_to_str(''.join(chr(e) for e in replace_access_bits))
		print("New Access bits (%d): %s" % (i, replace_access_bits_str))
		
		bytez[start] = replace_access_bits[0]
		bytez[start+1] = replace_access_bits[1]
		bytez[start+2] = replace_access_bits[2]
		
	return bytez
		

def main(args):
	filename = args[0]
	
	f = open(filename, "rb")
	data = f.read()
	bytez = set_access_bits(data)
	f.close()
	
	n_f = open('safe_' + filename, "wb")
	n_f.write(bytez)
	n_f.close()


if __name__ == "__main__":
	main(sys.argv[1:])