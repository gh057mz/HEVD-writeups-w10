import sys

LINE_WIDTH_LIMIT = 80
INDENTATION_SPACES = 4

with open(sys.argv[1], "rb") as input_file:
    file_data = input_file.read()

print("unsigned char payload[] = {")

hex_values = [f"0x{byte:02x}" for byte in file_data]
current_line = " " * INDENTATION_SPACES

for hex_value in hex_values:
    if len(current_line + hex_value + ",") > LINE_WIDTH_LIMIT:
        print(current_line.rstrip())
        current_line = " " * INDENTATION_SPACES
    current_line += hex_value + ", "

print(current_line.rstrip(", ") + "\n};")
