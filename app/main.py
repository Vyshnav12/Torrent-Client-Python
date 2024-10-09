import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!

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
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
