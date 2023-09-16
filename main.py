"""
    Mohammad Anas
    20L-1289
    BDS-7A
    Assignment 1
    Information Security
"""

def textInput(text):
    """
    Prompts the user for input, converts it to a hexadecimal string, and formats it to 4 characters.

    Args:
        text (str): The prompt message to display to the user.

    Raises:
        SystemExit: If an error occurs during input or conversion, the program exits.

    Returns:
        str: A 4-character hexadecimal string entered by the user.
    """
    try:
        user_input = input(text)
        hex_value = str(hex(int(user_input, 16)))
        hex_value = hex_value[2:]
        while len(hex_value) < 4:
            hex_value = '0' + hex_value
        return hex_value
    except Exception as e:
        print('Error:', e)
        raise SystemExit

def SubNibbles(input_hex, flag=True):
    """Perform SubNibbles operation on a 16-bit hexadecimal input.

    Args:
        input_hex (int or str): A 16-bit hexadecimal input as an integer or string.

    Returns:
        str: The result of the SubNibbles operation as a 16-bit hexadecimal string.
    """ 
    
    if isinstance(input_hex, str):
        input_hex = int(input_hex, 16)
        
    input_bin = bin(input_hex)[2:].zfill(16)
    nibbles = [input_bin[i:i+4] for i in range(0, len(input_bin), 4)]
    
    substitution_table = {
            '0000': '1010', '0001': '0000', '0010': '1001', '0011': '1110',
            '0100': '0110', '0101': '0011', '0110': '1111', '0111': '0101',
            '1000': '0001', '1001': '1101', '1010': '1100', '1011': '0111',
            '1100': '1011', '1101': '0100', '1110': '0010', '1111': '1000'
        }
    inverse_substitution_table = {v: k for k, v in substitution_table.items()}

    result_bin = ''.join([substitution_table[nibble] if flag else inverse_substitution_table[nibble] for nibble in nibbles])
    result =  hex(int(result_bin, 2))
    result = result[2:]
    
    if len(result) < 4:
        result = result.zfill(4)
        
    return result

def GenerateRoundKeys(input_key):
    """
    Generate two round keys, K1 and K2, from the given input key.

    Args:
        input_key (str): A 16-character hexadecimal string representing the input key.

    Returns:
        tuple: A tuple containing two 4-character hexadecimal strings representing K1 and K2.

    Raises:
        ValueError: If the input key is not a valid 16-character hexadecimal string.
    """

    # Check if the input_key is a hexadecimal string; if not, convert it
    if isinstance(input_key, str):
        input_key = int(input_key, 16)

    # Convert the integer input key to a 16-bit binary string with leading zeros
    input_binary = bin(input_key)[2:].zfill(16)

    # Split the binary string into nibbles (4-bit chunks)
    w0, w1, w2, w3 = [int(input_binary[i:i + 4], 2) for i in range(0, len(input_binary), 4)]
    
    # Define Rcon constants
    Rcon1 = 0b1110
    Rcon2 = 0b1010
    
    # Calculate w4, w5, w6, and w7
    w4 = w0 ^ int(SubNibbles(hex(w3)), 16) ^ Rcon1
    w5 = w1 ^ w4
    w6 = w2 ^ w5
    w7 = w3 ^ w6
    K1 = [w4, w5, w6, w7]
    
    # Calculate w8, w9, w10, and w11
    w8 = w4 ^ int(SubNibbles(hex(w7)), 16) ^ Rcon2
    w9 = w5 ^ w8
    w10 = w6 ^ w9 
    w11 = w7 ^ w10
    K2 = [w8, w9, w10, w11]

    K1_bits = [bin(val)[2:].zfill(4)[-4:] for val in K1]
    K2_bits = [bin(val)[2:].zfill(4)[-4:] for val in K2]
    
    # Convert K1_bits and K2_bits (lists of bit strings) to hexadecimal strings
    K1_hex = ''.join(hex(int(bit, 2))[2:] for bit in K1_bits)
    K2_hex = ''.join(hex(int(bit, 2))[2:] for bit in K2_bits)

    return K1_hex, K2_hex

def ShiftRow(input_block_hex):
    """
    Perform the ShiftRow operation on a 4-character hexadecimal string, swapping the first and third nibbles.

    Args:
        input_block_hex (str): A 4-character hexadecimal string representing a 16-bit value.
        
    Returns:
        str: A new 4-character hexadecimal string resulting from the row shift.
    """
    # Swap the first and third nibbles to perform the row shift
    swapped_block_hex = input_block_hex[2] + input_block_hex[1] + input_block_hex[0] + input_block_hex[3]

    return swapped_block_hex

def MultiplicationFiniteField(a, b):
    """
    Multiplies two 4-bit numbers in the finite field GF(2^4) using the irreducible polynomial x^4 + x + 1.

    Args:
        a (int): The first 4-bit number.
        b (int): The second 4-bit number.

    Returns:
        int: The product of a and b in the finite field GF(2^4).
    """
    
    a = int(a, 16)
    b = int(b, 16)
    m = 0

    while b > 0:
        if b & 1:  # Check if the least significant bit of b is 1
            m ^= a  
        a <<= 1  
        if a & 0x10:  # Check if the 4th bit of a is set
            a ^= 0x13  

        b >>= 1  

    return m

def MixColumns(input_block, flag=True):
    """
    MixColumns operation in AES encryption.

    Args:
        input_block_hex (str): A 4-character hexadecimal string representing the input block.

    Returns:
        str: A 4-character hexadecimal string representing the result of the MixColumns operation.
    """
    constant_matrix = "1441" if flag else "9229"

        
    d0 = (MultiplicationFiniteField(constant_matrix[0], input_block[0]) ^ MultiplicationFiniteField(constant_matrix[1], input_block[1]))
    d1 = (MultiplicationFiniteField(constant_matrix[2], input_block[0]) ^ MultiplicationFiniteField(constant_matrix[3], input_block[1]))
    
    d2 = (MultiplicationFiniteField(constant_matrix[0], input_block[2]) ^ MultiplicationFiniteField(constant_matrix[1], input_block[3]))
    d3 = (MultiplicationFiniteField(constant_matrix[2], input_block[2]) ^ MultiplicationFiniteField(constant_matrix[3], input_block[3]))

    output_block_hex = f"{d0:01x}{d1:01x}{d2:01x}{d3:01x}"
    return output_block_hex

def AddRoundKey(text_block_hex, key_hex):
    """
    Perform the AddRoundKey operation on a 4-character hexadecimal string.

    Args:
        text_block_hex (str): A 4-character hexadecimal string representing a 16-bit value.
        key_hex (str): A 4-character hexadecimal string representing a 16-bit key.

    Returns:
        str: A new 4-character hexadecimal string resulting from the XOR operation with the key.
    """
    result = ''
    for i in range(4):
        val = int(text_block_hex[i], 16) ^ int(key_hex[i], 16)
        val_hex = hex(val)
        result += val_hex[2]

    return result

if __name__ == "__main__":
    print("\n########################### D1\n")

    input_text_block = textInput("Enter a text block: ")
    subnibbles_result = SubNibbles(input_text_block)
    shiftrow_result = ShiftRow(input_text_block)
    mixcolumns_result = MixColumns(input_text_block)

    print(f"SubNibbles({input_text_block}): {subnibbles_result}")
    print(f"ShiftRow({input_text_block}): {shiftrow_result}")
    print(f"MixColumns({input_text_block}): {mixcolumns_result}")

    input_key = textInput("\nEnter a key: ")
    k1, k2 = GenerateRoundKeys(input_key)
    print(f"GenerateRoundKeys({input_key}): ({k1}, {k2})")

    #####################################################

    print("\n########################### D2\n")
    cipher_block = textInput('Enter the ciphertext block: ')
    
    input_key = textInput('Enter the key: ')
    k1, k2 = GenerateRoundKeys(input_key)

    cipher_block = ShiftRow(cipher_block)
    cipher_block = AddRoundKey(cipher_block, k2)
    cipher_block = SubNibbles(cipher_block, False)
    cipher_block = ShiftRow(cipher_block)
    cipher_block = MixColumns(cipher_block, False)
    cipher_block = AddRoundKey(cipher_block, k1)
    cipher_block = SubNibbles(cipher_block, False)

    print('Decrypted block:', cipher_block)

    #####################################################

    print('\n########################### D3\n')
    file = None
    try:
        print('Reading encrypted file secret.txt...')
        file = open('secret.txt', "r")
    except Exception as e:
        print("Error:", e)
        raise SystemExit
    encrypted_content = file.read()
    file.close()

    decryption_key = textInput('Enter the decryption key: ')
    k1, k2 = GenerateRoundKeys(decryption_key)

    encrypted_substrings = encrypted_content.split()

    decrypted_substrings = []
    for i in encrypted_substrings:
        inter = ShiftRow(i)
        inter = AddRoundKey(inter, k2)
        inter = SubNibbles(inter, False)
        inter = ShiftRow(inter)
        inter = MixColumns(inter, False)
        inter = AddRoundKey(inter, k1)
        inter = SubNibbles(inter, False)
        decrypted_substrings.append(inter)

    decrypted_string = ' '.join(decrypted_substrings)
    try:
        file = open('plain.txt', "w")
        file.write(decrypted_string)
        file.close()
    except Exception as e:
        print('Error:', e)

    decrypted_content = ''
    for i in decrypted_substrings:
        decrypted_content += chr(int(i[:2], 16))
        # Handling null padding (if exists)
        if int(i[2:], 16) != 0:
            decrypted_content += chr(int(i[2:], 16))

    print('\nDecrypted Result')
    print('--------------------')
    print(decrypted_content)  # Gentlemen, you can't fight in here. This is the war room.
    print('--------------------')