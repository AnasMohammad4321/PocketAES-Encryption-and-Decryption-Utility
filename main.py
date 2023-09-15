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
    
def SubNibbles(input_hex):
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

    result_bin = ''.join([substitution_table[nibble] for nibble in nibbles])

    return hex(int(result_bin, 2))

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

number = textInput("Enter a text block:")
print(f"SubNibbles({number}):{SubNibbles(number)}")

key = textInput("Enter a key:")
print(f"GenerateRoundKeys({key}):{GenerateRoundKeys(key)}")