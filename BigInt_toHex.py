##=========================================================== ##
# Description: Script that converts big integer value to hex 
## Author: Userhonest
## 07.10.23

import sys

def bigIntToHex(strBigIntValue):
    intBigIntValue = int(strBigIntValue)
    return hex(intBigIntValue).rstrip("L").lstrip("0x") or "0"

def main():
    if len(sys.argv) != 2:
        print("Usage: python scriptname.py <big_integer_value>")
        sys.exit(1)
    
    strBigIntValue = sys.argv[1]
    strHexValue = bigIntToHex(strBigIntValue)
    
    print("")
    print("Result =" , strHexValue.upper())

if __name__ == "__main__":
    main()

## === end of file ===  ##
