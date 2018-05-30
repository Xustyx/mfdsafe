#!/usr/bin/env python

import codecs
import sys
import argparse
import logging


# Secure types bits
SCTYPES = {
	"transport": [False, False, True],
	"default": [False, True, True],
	"minimal": [True, False, True]
}


# Map for each case to a secure type
MCTYPES = {
	"000": "transport",
	"001": "transport",
	"010": "transport",
	"011": "default",
	"100": "default",
	"101": "minimal",
	"110": "default",
	"111": "default"
}


SECTOR_SIZE = 64
ACCESS_BITS_OFFSET = 54
ACCESS_BITS_SIZE = 3
DEFAULT_LOGLEVEL = logging.INFO


def get_bit(value, index):
	return (value & (1<<index)) != 0


def set_bit(value, index, x):
	if x:
		return apply_bit(value, index)

	return clear_bit(value, index)


def apply_bit(value, index):
	return value | (1<<index)


def clear_bit(value, index):
	return value & ~(1<<index)

def access_bits_to_str(access_bits):
	access_bits_str = "%i%i%i" % (tuple(access_bits))
	return access_bits_str

def access_bytes_to_str(access_bytes):
	access_bytes_str = codecs.encode(access_bytes, 'hex')

	if not isinstance(access_bytes_str, str):
		access_bytes_str = str(access_bytes_str, 'ascii')
		
	return access_bytes_str


def new_access_bytes(access_bytes, replace_access_bits):
	new_access_bytes = []

	new_access_bytes.append(set_bit(map(ord, access_bytes)[0], 7, not replace_access_bits[1]))
	new_access_bytes[0] = set_bit(new_access_bytes[0], 3, not replace_access_bits[0])

	new_access_bytes.append(set_bit(map(ord, access_bytes)[1], 7, replace_access_bits[0]))
	new_access_bytes[1] = set_bit(new_access_bytes[1], 3, not replace_access_bits[2])

	new_access_bytes.append(set_bit(map(ord, access_bytes)[2], 7, replace_access_bits[2]))
	new_access_bytes[2] = set_bit(new_access_bytes[2], 3, replace_access_bits[1])

	return new_access_bytes


def new_access_bits(access_bits, ctype):
	if ctype is not "none":
		logging.debug("Using argument condition type : %s" % ctype)
		sk_sctype = ctype
	else:
		sk_mctype = access_bits_to_str(access_bits)
		sk_sctype = MCTYPES.get(sk_mctype)

	logging.debug("Using condition type: %s" % sk_sctype)

	return SCTYPES.get(sk_sctype)


def get_access_bits(access_bytes):
	old_access_bits = []
	nold_access_bits = []

	nold_access_bits.append(get_bit(map(ord, access_bytes)[0],3))
	nold_access_bits.append(get_bit(map(ord, access_bytes)[0],7))
	nold_access_bits.append(get_bit(map(ord, access_bytes)[1],3))

	old_access_bits.append(get_bit(map(ord, access_bytes)[1],7))
	old_access_bits.append(get_bit(map(ord, access_bytes)[2],3))
	old_access_bits.append(get_bit(map(ord, access_bytes)[2],7))
	
	nold_access_bits_str = access_bits_to_str(nold_access_bits)
	old_access_bits_str = access_bits_to_str(old_access_bits)
	logging.debug("Actual access bits: (%s)/!(%s)" % (old_access_bits_str, nold_access_bits_str))

	for i in range(0,3):
		access_bit = old_access_bits[i]
		naccess_bit = nold_access_bits[i]

		logging.debug("Checking acces bit c%i: (%i)/!(%i)" % (i+1, access_bit, naccess_bit))

		if(access_bit is naccess_bit):
			logging.error("Access bit c%i corrupted: (%i)/!(%i)" % (i+1, access_bit, naccess_bit))
			logging.warning("Corrupted access bits, using default condition type")
			return SCTYPES.get("default")
	
	return old_access_bits


def set_access_bytes(data, ctype):
	bytez = bytearray(data)
	
	for i in range(0, 16):
		start = i * SECTOR_SIZE + ACCESS_BITS_OFFSET
		end = start + ACCESS_BITS_SIZE


		access_bytes = data[start:end]
		access_bytes_str = access_bytes_to_str(access_bytes)
		logging.info("Actual access bytes of sector (%d): %s" % (i, access_bytes_str))

		access_bits = get_access_bits(access_bytes)
		access_bits_str = access_bits_to_str(access_bits)
		logging.info("Actual condition bits of sector (%d): %s" % (i, access_bits_str))


		replace_access_bits = new_access_bits(access_bits, ctype)
		replace_access_bits_str = access_bits_to_str(replace_access_bits)
		logging.info("New condition bits of sector (%d): %s" % (i, replace_access_bits_str))
		
		replace_access_bytes = new_access_bytes(access_bytes, replace_access_bits)
		replace_access_bytes_str = access_bytes_to_str(''.join(chr(e) for e in replace_access_bytes))
		logging.info("New access bytes of sector (%d): %s" % (i, replace_access_bytes_str))
		

		bytez[start] = replace_access_bytes[0]
		bytez[start+1] = replace_access_bytes[1]
		bytez[start+2] = replace_access_bytes[2]
		
	return bytez
		

def main(args):
	loglevel = DEFAULT_LOGLEVEL

	if args.verbose:
		loglevel = logging.DEBUG

	logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)

	f = args.INPUT
	data = f.read()
	bytez = set_access_bytes(data, args.type)
	f.close()
	
	n_f = open(args.output, "wb")
	n_f.write(bytez)
	n_f.close()


def get_args():
	parser = argparse.ArgumentParser(
		description="Creates a new dump file from Mifare Classic 1k dump with secure access bits to avoid brick the card.")

	parser.add_argument(
		"-o",
		"--output", 
		type=str,
		required=True,
		help="output dump filename.")
	parser.add_argument(
		"-t",
		"--type", 
		choices=["transport", "default"],
		default="none",
		help="force all access bits to selected type.")
	parser.add_argument(
		"-v",
		"--verbose",
		help="increase output verbosity",
		action="store_true")
	parser.add_argument(
		"INPUT",
		type=argparse.FileType('rb'),
		help="dump input file."
        "Must be a valid Mifare Classic 1k dump.")

	args = parser.parse_args()

	return args


if __name__ == "__main__":
	args = get_args()
	main(args)
