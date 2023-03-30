# hashGENIE
hashGENIE generates hash values for a given string using various hash algorithms.

## How this script works?

- This script generates hash values for a given string using various hash algorithms.
- It takes the user input as a command-line argument or prompts the user to enter a string to be hashed.
- It then uses the hashlib and hmac modules of the Python 3 standard library to generate hash values for the given string using a selection of hash algorithms, including md5, sha1, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, ripemd160, and hmac.

- The program creates an instance of the HashTable class to store the generated hash values and uses the PrettyTable module to display the hash values in a formatted table.
- The HashTable class contains a method named calculate_hash, which takes an algorithm name as an argument and generates the hash value using that algorithm.
- The generated hash value is then added to the table using the add_row method of the PrettyTable module.
- Once the hash values for all the selected algorithms have been generated and added to the table, the program calls the print_table method of the HashTable class to display the table of hash values.
- The program also includes a help message that can be accessed by passing the -h or --help command-line argument. The help message provides information on how to use the program and its available options.

Overall, this program provides a convenient way to generate hash values for a given string using a selection of hash algorithms, making it useful for various security and encryption applications.

## Requirements

Install your libraries:
```bash
pip3 install hashlib, hmac, prettytable
```

## Permissions

Ensure you give the script permissions to execute. Do the following from the terminal:
```bash
sudo chmod +x hashGENIE.py
```

## Usage

Help:
```
sudo python3 hashGenie.py -h
Password:
.__                     .__       ________ ___________ _______   .___ ___________
|  |__  _____     ______|  |__   /  _____/ \_   _____/ \      \  |   |\_   _____/
|  |  \ \__  \   /  ___/|  |  \ /   \  ___  |    __)_  /   |   \ |   | |    __)_
|   Y  \ / __ \_ \___ \ |   Y  \\    \_\  \ |        \/    |    \|   | |        \
|___|  /(____  //____  >|___|  / \______  //_______  /\____|__  /|___|/_______  /
     \/      \/      \/      \/         \/         \/         \/              \/

Usage: python hashGENIE.py [-h] [STRING]

Calculate hash values for a given string using various hash algorithms.

positional arguments:
  STRING         the string to be hashed

optional arguments:
  -h, --help     show this help message and exit
```

Basic:
```bash
sudo python3 hashGENIE.py
```

## Example script
```python
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
```

## Example output
```
sudo python3 hashGenie.py
.__                     .__       ________ ___________ _______   .___ ___________
|  |__  _____     ______|  |__   /  _____/ \_   _____/ \      \  |   |\_   _____/
|  |  \ \__  \   /  ___/|  |  \ /   \  ___  |    __)_  /   |   \ |   | |    __)_
|   Y  \ / __ \_ \___ \ |   Y  \\    \_\  \ |        \/    |    \|   | |        \
|___|  /(____  //____  >|___|  / \______  //_______  /\____|__  /|___|/_______  /
     \/      \/      \/      \/         \/         \/         \/              \/

Enter a string to hash: Pa$$w0rd
+-----------+----------------------------------------------------------------------------------------------------------------------------------+
| Algorithm |                                                               Hash                                                               |
+-----------+----------------------------------------------------------------------------------------------------------------------------------+
|    MD5    |                                                 3cc31cd246149aec68079241e71e98f6                                                 |
| RIPEMD160 |                                             a615382e0575e21cbe91f5f7967bffc849e2377b                                             |
|    SHA1   |                                             02726d40f378e716981c4321d60ba3a325ed6a4c                                             |
|   SHA256  |                                 97c94ebe5d767a353b77f3c0ce2d429741f2e8c99473c3c150e2faa3d14c9da6                                 |
|   SHA384  |                 6e438212f7c404d61a8d4cd8738b4a56a808eaafd65d509a2c0c865da9d63b9c28fadb7f7cbd7c48ec051bda64dd787a                 |
|   SHA512  | e239f67756bba3af660e4226c340183a9ca4bdc40038c0cfdea2fbaa59605be32548df2535e5a9f9ceedb12d9666c6fb153ada99830ed5cd84eb0c2c4d00260a |
|  SHA3_224 |                                     0888bae477a78f850286628041b594af9e6a4aaadb14c4569e56b5c8                                     |
|  SHA3_256 |                                 148aa5576734e89ace0fc629e6fe2a32e13a1f1859355dc660210ec09fe40271                                 |
|  SHA3_384 |                 6876196c7b203d275935b82d76d0ca8ad03e6f7ad5bf4e9c941cda56abc1b6fe2898ba7463a1fe0e946a9bfd5d0dc51b                 |
|  SHA3_512 | 5b0c4bdd0d929d058f18645e3503ab5f103a5f4d215cf0f0bf2fef822425a586667326760ca68337e04061f43a0497d2a30a18d909a3741b59ea256b8f77a535 |
|    HMAC   |                                 2f1d2d6d971a8c33fd420f66fd0c65671181ba6dacf9832ece5f661de4fde7f8                                 |
+-----------+----------------------------------------------------------------------------------------------------------------------------------+
```

## License Information

This library is released under the [Creative Commons ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/). You are welcome to use this library for commercial purposes. For attribution, we ask that when you begin to use our code, you email us with a link to the product being created and/or sold. We want bragging rights that we helped (in a very small part) to create your 9th world wonder. We would like the opportunity to feature your work on our homepage.
