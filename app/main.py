import json
import sys
import os

import bencodepy # type: ignore
import hashlib
import requests
from urllib.parse import urlencode
import struct
import socket
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

def info_hash(torrent_fp):
    with open(torrent_fp, "rb") as f:
            torrent_data = f.read()

    torrent_dict = decode_bencode(torrent_data)
    
    print(f"Tracker URL: {torrent_dict['announce'].decode()}")
    print(f"Length: {torrent_dict['info']['length']}")
    info2 = torrent_dict['info']
    info2_hex = hashlib.sha1(bencodepy.encode(info2)).hexdigest()
    print(f"Info Hash: {info2_hex}")
    print(f"Piece Length: {torrent_dict['info']['piece length']}")
    print(f"Pieces: {torrent_dict['info']['pieces'].hex()}")

def peers(torrent_fp):
    with open(torrent_fp, "rb") as f:
            torrent_data = f.read()

    torrent_dict = decode_bencode(torrent_data)
    info2 = torrent_dict['info']
    info2_hex = hashlib.sha1(bencodepy.encode(info2)).digest()
    
    params = {
        "info_hash": info2_hex,
        "peer_id": os.urandom(20),
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

def handshake(torrent_fp, ip, port):
    
    with open(torrent_fp, "rb") as f:
            torrent_data = f.read()

    torrent = decode_bencode(torrent_data)
    peer_id = os.urandom(20)
    info = torrent['info']
    info2_hex = hashlib.sha1(bencodepy.encode(info)).digest()
        
    handshake_message = struct.pack('!B19s8x20s20s', 19, b"BitTorrent protocol", info2_hex, peer_id)
        
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((ip, port))
    server_socket.send(handshake_message)
        
    recieved_message = server_socket.recv(1024)
    recieved_message = struct.unpack('!B19s8x20s20s', recieved_message)
    print(f"Peer ID: {recieved_message[3].hex()}")
    
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
        info_hash(torrent_file_path)
        
    elif command == "peers":
        torrent_file_path = sys.argv[2]
        peers(torrent_file_path)
        
    elif command == "handshake":
        torrent_file_path = sys.argv[2]
        ip = sys.argv[3].split(":")[0]
        port = int(sys.argv[3].split(":")[1])
        
        handshake(torrent_file_path, ip, port)
            
    # elif command == "download_piece":
    #     torrent_file_path = sys.argv[2]
        
        
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
