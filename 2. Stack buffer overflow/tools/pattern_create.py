#!/usr/bin/env python3

import sys
import struct

def print_help():
    print('Usage: {} (create | offset) <value> <buflen>'.format(sys.argv[0]))

def pattern_create(length=8192):
    pattern = ''
    parts = ['A', 'a', '0']
    try:
        length = int(length)  # Ensure length is always an integer
    except ValueError:
        print_help()
        sys.exit(254)
    while len(pattern) < length:
        pattern += parts[len(pattern) % 3]
        if len(pattern) % 3 == 0:
            parts[2] = chr(ord(parts[2]) + 1)
            if parts[2] > '9':
                parts[2] = '0'
                parts[1] = chr(ord(parts[1]) + 1)
                if parts[1] > 'z':
                    parts[1] = 'a'
                    parts[0] = chr(ord(parts[0]) + 1)
                    if parts[0] > 'Z':
                        parts[0] = 'A'
    return pattern

def pattern_offset(value, length=8192):
    try:
        if isinstance(value, str) and value.startswith('0x'):
            value = struct.pack('<I', int(value, 16)).strip(b'\x00').decode()
    except ValueError:
        print_help()
        sys.exit(254)
    pattern = pattern_create(length)  # Now pattern_create receives a valid integer
    try:
        return pattern.index(value)
    except ValueError:
        return 'Not found'

def main():
    if len(sys.argv) < 3 or sys.argv[1].lower() not in ['create', 'offset']:
        print_help()
        sys.exit(255)

    command = sys.argv[1].lower()
    num_value = sys.argv[2]

    if command == 'create':
        print(pattern_create(int(num_value)))
    elif len(sys.argv) == 4:
        print(pattern_offset(num_value, int(sys.argv[3])))

if __name__ == '__main__':
    main()
