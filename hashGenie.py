# -*- coding: utf-8 -*-
# Author : Dimitrios Zacharopoulos
# All copyrights to Obipixel Ltd
# 20 March 2023

import sys
import hashlib
import hmac
from prettytable import PrettyTable

# Print the ASCII art
print(".__                     .__       ________ ___________ _______   .___ ___________ ")
print("|  |__  _____     ______|  |__   /  _____/ \_   _____/ \      \  |   |\_   _____/ ")
print("|  |  \ \__  \   /  ___/|  |  \ /   \  ___  |    __)_  /   |   \ |   | |    __)_  ")
print("|   Y  \ / __ \_ \___ \ |   Y  \\\    \_\  \ |        \/    |    \|   | |        \ ")
print("|___|  /(____  //____  >|___|  / \______  //_______  /\____|__  /|___|/_______  / ")
print("     \/      \/      \/      \/         \/         \/         \/              \/  ")
print()

class HashTable:
    def __init__(self, user_input):
        self.hash_algorithms = [
            'md5', 'md6', 'ripemd160', 'sha1', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'hmac'
        ]
        self.user_input = user_input
        self.table = PrettyTable(['Algorithm', 'Hash'])

    def calculate_hash(self, algorithm):
        try:
            if algorithm == 'hmac':
                # Use a random key for HMAC
                key = b'secret_key'
                hash_object = hmac.new(key, self.user_input.encode(), hashlib.sha256)
                hash_value = hash_object.hexdigest()
            else:
                hash_object = hashlib.new(algorithm)
                hash_object.update(self.user_input.encode())
                hash_value = hash_object.hexdigest()
            self.table.add_row([algorithm.upper(), hash_value])
        except ValueError:
            # Some algorithms require additional parameters
            pass

    def print_table(self):
        print(self.table)

# Define the help message
HELP_MSG = """Usage: python hashGENIE.py [-h] [STRING]

Calculate hash values for a given string using various hash algorithms.

positional arguments:
  STRING         the string to be hashed

optional arguments:
  -h, --help     show this help message and exit"""

# Check for command-line options
if len(sys.argv) > 1 and sys.argv[1] == '-h':
    print(HELP_MSG)
    sys.exit()

# Get user input
if len(sys.argv) > 1:
    user_input = sys.argv[1]
else:
    user_input = input('Enter a string to hash: ')

# Create hash table
hash_table = HashTable(user_input)

# Calculate hash for each algorithm and add to table
for algorithm in hash_table.hash_algorithms:
    hash_table.calculate_hash(algorithm)

# Print the table
hash_table.print_table()
