import json
import sys
import socket
import hashlib
import requests
import struct
import os


# Decoding bencoded data
def decode_int(bencoded_value):
    if chr(bencoded_value[0]) != "i":
        raise ValueError("Not an integer")
    end_int = bencoded_value.find(b"e")
    if end_int == -1:
        raise ValueError("Not an integer")
    decoded_int = int(bencoded_value[1:end_int])
    bencoded_remainder = bencoded_value[end_int + 1 :]
    return decoded_int, bencoded_remainder

def decode_dict(bencoded_value):
    if chr(bencoded_value[0]) != "d":
        raise ValueError("Not a dict")
    bencoded_remainder = bencoded_value[1:]
    decoded_dict = {}
    while chr(bencoded_remainder[0]) != "e":
        decoded_key, bencoded_remainder = decode_string(bencoded_remainder)
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_dict[decoded_key.decode()] = decoded_value
    return decoded_dict, bencoded_remainder[1:]

def decode_list(bencoded_value):
    if chr(bencoded_value[0]) != "l":
        raise ValueError("Not a list")
    bencoded_remainder = bencoded_value[1:]
    decoded_list = []
    while chr(bencoded_remainder[0]) != "e":
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_list.append(decoded_value)
    return decoded_list, bencoded_remainder[1:]

def decode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Not a string")
    length_string = int(bencoded_value[:first_colon_index])
    decoded_string = bencoded_value[
        first_colon_index + 1 : first_colon_index + 1 + length_string
    ]
    bencoded_remainder = bencoded_value[first_colon_index + 1 + length_string :]
    return decoded_string, bencoded_remainder

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0]) == "i":
        return decode_int(bencoded_value)
    elif chr(bencoded_value[0]) == "l":
        return decode_list(bencoded_value)
    elif chr(bencoded_value[0]) == "d":
        return decode_dict(bencoded_value)
    else:
        raise NotImplementedError(
            f"We only support strings, integers, lists, and dicts."
        )
#################### Decoding end ##################################

    
# Encoding data in bencode format
def bencode_bytes(value):
    length = len(value)
    return str(length).encode() + b":" + value


def bencode_int(value):
    return ("i" + str(value) + "e").encode()

def bencode_string(value):
    length = len(value)
    return (str(length) + ":" + value).encode()

def bencode_dict(value):
    result = b"d"
    for k in value:
        result += bencode(k) + bencode(value[k])
    return result + b"e"

def bencode_list(value):
    result = b"l"
    for i in value:
        result += bencode(i)
    return result + b"e"

def bencode(value):
    if isinstance(value, str):
        return bencode_string(value)
    elif isinstance(value, bytes):
        return bencode_bytes(value)
    elif isinstance(value, int):
        return bencode_int(value)
    elif isinstance(value, list):
        return bencode_list(value)
    elif isinstance(value, dict):
        return bencode_dict(value)
    else:
        raise ValueError("Can only bencode strings, ints, lists, or dicts.")

#################### Encoding end ##################################

def pieces_hash_list(pieces):
    n = 20
    if len(pieces) % n != 0:
        raise ValueError("Piece hashes do not add up to a multiple of", n, "bytes.")
    return [pieces[i : i + n] for i in range(0, len(pieces), n)]

# printing the torrent file info by passing and using bencode decode
# Note that the file is in binary format so use bytes
def get_torrentinfo(filename):
    with open(filename, "rb") as f:
        bencoded_content = f.read()
        decoded_value, remainder = decode_bencode(bencoded_content)
        if remainder:
            raise ValueError("Undecoded remainder.")
        print("Tracker URL:", decoded_value["announce"].decode())
        print("Length:", decoded_value["info"]["length"])

        # info hash 
        info_hash = hashlib.sha1(bencode(decoded_value["info"])).hexdigest()
        print("Info Hash:", info_hash)

        print("Piece Length:", decoded_value["info"]["piece length"])
        print("Pieces Hash:")
        hashes = pieces_hash_list(decoded_value["info"]["pieces"])
        for h in hashes:
            print(h.hex())


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # converting to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        if len(sys.argv) != 3:
            raise NotImplementedError(f"Usage: {sys.argv[0]} info filename")
        filename = sys.argv[2]
        get_torrentinfo(filename)

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
