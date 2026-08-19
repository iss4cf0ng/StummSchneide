# StummSchneide

StummSchneide is an implant tool targeting Windows platforms. It is a proof-of-concept implant for DustHarbor, inspired by Meterpreter.

# Disclaimer

This project is designed for educational purposes only.

Please do **NOT** use it for illegal activities. The author is not responsible for any damage caused by this project.

# Features

Inspired by Meterpreter, StummSchneide's shellcode downloads a DLL from the C2 server and perform reflective DLL injection.

# Usage

On Linux (C2 server):

```bash
python3 server.py
```

On Windows (target):

```batch
loader.exe
```
