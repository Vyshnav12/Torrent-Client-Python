import json
import sys

import bencodepy
import hashlib
from random import choice
from string import ascii_uppercase
import requests
from urllib.parse import urlencode
import struct
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    def parse_string(data):
        length, string = data.split(b":", 1)
        length = int(length)
        return string[:length], string[length:]
    
    def decode(data):
        if chr(data[0]).isdigit():
            return parse_string(data)
        elif data.startswith(b"i"):
            end = data.index(b"e")
            return int(data[1:end]), data[end+1:]
        elif data.startswith(b"l"):
            data = data[1:]
            elements = []
            while not data.startswith(b"e"):
                item, data = decode(data)
                elements.append(item)
            return elements, data[1:]
        elif data.startswith(b"d"):
            data = data[1:]
            dictionary = {}
            while not data.startswith(b"e"):
                key, data = decode(data)
                if isinstance(key, bytes):
                    key = key.decode()
                value, data = decode(data)
                dictionary[key] = value
            return dictionary, data[1:]
        else: 
            raise ValueError("Invalid encoded value")

    decoded_val, _ = decode(bencoded_value)
    return decoded_val

def main():
    command = sys.argv[1]


    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
        
    elif command == "info":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as f:
            torrent_data = f.read()

        torrent_dict = decode_bencode(torrent_data)

        print(f"Tracker URL: {torrent_dict['announce'].decode()}")
        print(f"Length: {torrent_dict['info']['length']}")
        info2 = torrent_dict['info']
        info2_hex = hashlib.sha1(bencodepy.encode(info2)).hexdigest()
        print(f"Info Hash: {info2_hex}")
        print(f"Piece Length: {torrent_dict['info']['piece length']}")
        print(f"Pieces: {torrent_dict['info']['pieces'].hex()}")
        
    elif command == "peers":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as f:
            torrent_data = f.read()

        torrent_dict = decode_bencode(torrent_data)
        info2 = torrent_dict['info']
        info2_hex = hashlib.sha1(bencodepy.encode(info2)).digest()
        
        params = {
            "info_hash": info2_hex,
            "peer_id": "".join(choice(ascii_uppercase) for _ in range(20)),
            "port": "6881",
            "uploaded": "0",
            "downloaded": "0",
            "left": torrent_dict['info']['length'],
            "compact": "1",
        }
        
        response = requests.get(torrent_dict['announce'].decode() + "?" + urlencode(params))
        response_dict = decode_bencode(response.content)
        peers = response_dict['peers']
        
        for i in range(0, len(response_dict['peers']), 6):
            ip = peers[i:i+4]
            port = peers[i+4:i+6]
            
            ip = '.'.join(str(ips) for ips in ip)
            port = struct.unpack('!H', port)[0]
            print(f"{ip}:{port}")
        
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
