"""
    Mohammad Anas
    20L-1289
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
        textBlock = input(text)
        textBlock = str(hex(int(textBlock, 16)))
        textBlock = textBlock[2:]
        while len(textBlock) < 4:
            textBlock = '0' + textBlock
        return textBlock
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
    input_bin = bin(input_key)[2:].zfill(16)

    # Split the binary string into nibbles (4-bit chunks)
    w0, w1, w2, w3 = [int(input_bin[i:i + 4], 2) for i in range(0, len(input_bin), 4)]
    
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
    output_block_hex = input_block_hex[2] + input_block_hex[1] + input_block_hex[0] + input_block_hex[3]

    return output_block_hex

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
            m ^= a  # XOR operation

        a <<= 1  # Left shift a by 1 bit
        if a & 0x10:  # Check if the 4th bit of a is set
            a ^= 0x13  # XOR with irreducible polynomial x^4 + x + 1

        b >>= 1  # Right shift b by 1 bit

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

    # Convert the result to a 4-character hexadecimal string
    output_block_hex = f"{d0:01x}{d1:01x}{d2:01x}{d3:01x}"

    return output_block_hex

# Function to perform AddRoundKey operation on text block
def AddRoundKey(textBlock, key):
    temp = ''
    for i in range(4):
        val = int(textBlock[i],16) ^ int(key[i],16)
        val = str(hex(val))
        temp += val[2]
    return temp

if __name__ == "__main__":
    print("Mohammad Anas\n20L-1289\nAssignment 1\nInformation Security")
    print("\n########################### D1\n")

    number = textInput("Enter a text block: ")
    print(f"SubNibbles({number}): {SubNibbles(number)}")
    print(f"ShiftRow({number}): {ShiftRow(number)}")
    print(f"MixColumns({number}): {MixColumns(number)}")

    key = textInput("Enter a key:")
    print(f"GenerateRoundKeys({key}): {GenerateRoundKeys(key)}")

    #####################################################

    print("\n########################### D2\n")
    cipherBlock = textInput('Enter the ciphertext block: ')
    # cipherBlock = 'f3d7'

    key = textInput('Enter the key: ')
    # key = '40ee'
    k1, k2 = GenerateRoundKeys(key)

    cipherBlock = ShiftRow(cipherBlock)
    cipherBlock = AddRoundKey(cipherBlock, k2)
    cipherBlock = SubNibbles(cipherBlock, False)
    cipherBlock = ShiftRow(cipherBlock)
    cipherBlock = MixColumns(cipherBlock, False)
    cipherBlock = AddRoundKey(cipherBlock, k1)
    cipherBlock = SubNibbles(cipherBlock, False)

    print(cipherBlock)

    #####################################################

    print('\n########################### D3\n')
    file = None
    try:
        print('Reading encrypted file secret.txt...')
        file = open('secret.txt', "r")
    except Exception as e:
        print("Error:", e)
        raise SystemExit
    encryptedContent = file.read()
    file.close()

    key = textInput('Enter the decryption key: ')
    # key = '149c'
    k1, k2 = GenerateRoundKeys(key)

    encryptedSubStrings = encryptedContent.split()
    print(encryptedContent)

    decryptedSubStrings = []
    for i in encryptedSubStrings:
        inter = ShiftRow(i)
        inter = AddRoundKey(inter, k2)
        inter = SubNibbles(inter, False)
        inter = ShiftRow(inter)
        inter = MixColumns(inter, False)
        inter = AddRoundKey(inter, k1)
        inter = SubNibbles(inter, False)
        decryptedSubStrings.append(inter)

    decryptedString = ' '.join(decryptedSubStrings)
    try:
        file = open('plain.txt', "w")
        file.write(decryptedString)
        file.close()
    except Exception as e:
        print('Error:', e)

    decryptedContent = ''
    for i in decryptedSubStrings:
        decryptedContent += chr(int(i[:2],16))
        # handling null padding (if exists)
        if int(i[2:],16) != 0: decryptedContent += chr(int(i[2:],16))

    print('\nDecrypted Result')
    print('--------------------')
    print(decryptedContent) # Gentlemen, you can't fight in here. This is the war room.
    print('--------------------')