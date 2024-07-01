import re
import datetime
import path_nfc_file

"""_summary_

This script is designed to read NFC files, extract relevant 
blocks of data, compare blocks from multiple files, and analyze 
differences to identify potential patterns.
"""

# Opens an NFC file in read mode and returns it as a string
def read_nfc_file(file_path):
    with open(file_path, 'r') as f:
        return f.read()

# Extract data blocks from NFC files and iterate to extract 
# lines containing hexadecimal data blocks. The data is 
# then stored in a dictionary.
def extract_blocks(nfc_data):
    block_pattern = re.compile(r'Block (\d+): ([0-9A-Fa-f ]+)')
    return {int(match.group(1)): match.group(2).split() for line in nfc_data.splitlines() if (match := block_pattern.match(line))}

# Retrieves files and boots a dictionary to store 
# the conversion.
# **To be modified by the file(s) to be analyzed**
def get_hex_data():
    file_paths = [
        path_nfc_file.home_1_file_path,
        path_nfc_file.home_2_file_path,
        path_nfc_file.home_3_file_path,
        path_nfc_file.home_4_file_path,
        path_nfc_file.home_5_file_path,
        path_nfc_file.home_6_file_path
    ]
    
    return {file_path: extract_blocks(read_nfc_file(file_path)) for file_path in file_paths}

# Comparison of data blocks in different files 
# by iterating over each block index. If bytes 
# differ between files, calculate the sector 
# index.
def compare_blocks(*block_dicts):
    all_blocks = set().union(*[blocks.keys() for blocks in block_dicts])
    differences = []
    
    for block_index in all_blocks:
        blocks = [blocks.get(block_index, ['??'] * 16) for blocks in block_dicts]
        for byte_index, bytes in enumerate(zip(*blocks)):
            if len(set(bytes)) > 1:
                sector_index = block_index // 4
                differences.append((sector_index, block_index, byte_index, *blocks))
                break  
    
    return differences

# Returns the sector and block of a block number, 
# following the memory architecture of "Mifare 
# Classic 1K" cards.
def get_sector_block(block_num):
    if block_num < 128:
        return block_num // 4, block_num % 4
    return 32 + (block_num - 128) // 16, (block_num - 128) % 16

# Takes the list of differences as input. For each difference, 
# retrieves the block number and data blocks of the five files, 
# as well as the corresponding sector and block. Displays 
# information for each block (hexadecimal and ASCII conversion). 
# Compares each block byte to detect differences and displays 
# them. If the bytes are numbers, calculate the numerical 
# differences and try to interpret bytes as Unix timestamps 
# and display them.
def analyze_differences(differences):
    reported_blocks = set()
    for diff in differences:
        sector_index, block_index, byte_index, *blocks = diff
        if (sector_index, block_index) in reported_blocks:
            continue
        
        reported_blocks.add((sector_index, block_index))
        
        print(f"\n \nSecteur {sector_index}, Bloc {block_index} (Adresse linéaire {block_index}): \n")
        for i, block in enumerate(blocks, 1):
            print(f"  Hex block file {i} : {' '.join(block)}")
        
        ascii_blocks = [''.join(chr(int(byte, 16)) if 32 <= int(byte, 16) <= 126 else '.' for byte in block) for block in blocks]
        for i, ascii_block in enumerate(ascii_blocks, 1):
            print(f"  ASCII conversion file {i} : {ascii_block}")
        
        changes = [(j, *bytes) for j, bytes in enumerate(zip(*blocks)) if len(set(bytes)) > 1]
        
        if changes:
            print("\n  CHANGES DETECTED :")
            for change in changes:
                print(f"\n    Byte {change[0]}  : {' -> '.join(change[1:])}")
                try:
                    ascii_values = [chr(int(byte, 16)) if 32 <= int(byte, 16) <= 126 else '.' for byte in change[1:]]
                    print(f"    ASCII   : {' -> '.join(ascii_values)}")
                except:  # noqa: E722
                    print("    ASCII    : Not convertible")
                
                # Display decimal values
                decimal_values = [int(byte, 16) for byte in change[1:]]
                print(f"    Decimal : {' -> '.join(map(str, decimal_values))}")
                
                # Try to deduce the type of data (e.g. counter)
                if all(byte.isdigit() for byte in change[1:]):
                    diffs = [int(change[i+2]) - int(change[i+1]) for i in range(4)]
                    total_diff = sum(diffs)
                    print(f"\n    Digital difference : {total_diff}")
                    print(f"    Digital difference between each file : {' -> '.join(map(str, diffs))}")
                else:
                    # Try to interpret as timestamp  
                    try:
                        timestamps = [int(byte, 16) for byte in change[1:]]
                        for i, timestamp in enumerate(timestamps, 1):
                            print(f"    Timestamp {i} : {datetime.datetime.fromtimestamp(timestamp)}")
                    except:  # noqa: E722
                        pass

def main():
    # **To be modified by the file(s) to be analyzed**
    file_paths = [
        path_nfc_file.home_1_file_path,
        path_nfc_file.home_2_file_path,
        path_nfc_file.home_3_file_path,
        path_nfc_file.home_4_file_path,
        path_nfc_file.home_5_file_path,
        path_nfc_file.home_6_file_path
    ]
    
    hex_data_dict = get_hex_data()
    blocks = [hex_data_dict[file_path] for file_path in file_paths]
    
    differences = compare_blocks(*blocks)
    print("\n   TARGET :")
    print("\n   Detection and analysis of a potential NFC copy protection system")
    print("\n   All scans after the first use were performed after each new use \n   of the NFC badge.\n")
    # **To be modified by the file(s) to be analyzed**
    for i, date in enumerate([
        path_nfc_file.date_file_1,
        path_nfc_file.date_file_2,
        path_nfc_file.date_file_3,
        path_nfc_file.date_file_4,
        path_nfc_file.date_file_5,
        path_nfc_file.date_file_6], 1):
        print(f"        File {i} was used on : {date}")
    
    analyze_differences(differences)
    print()

if __name__ == "__main__":
    main()
