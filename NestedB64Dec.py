#" Script that decodes nested base64 data 
# Author: UserHonest

import base64
import sys

def repeated_decode(strEncodedData):
    intDecodeCount = 0
    while True:
        try:
            strDecodedData = base64.b64decode(strEncodedData).decode('utf-8')
            intDecodeCount += 1
            
            if "pico" in strDecodedData:
                return strDecodedData, intDecodeCount

            if strEncodedData == strDecodedData:
                break

            strEncodedData = strDecodedData
        except Exception:
            break
    return strEncodedData, intDecodeCount

if len(sys.argv) < 2:
    print("Please provide a file name as an argument. Usage: python script.py <filename>")
    sys.exit(1)

strFilename = sys.argv[1]

# Read from the provided file
with open(strFilename, "r") as objFile:
    strEncodedText = objFile.read().strip()

strDecodedText, intDecodingCount = repeated_decode(strEncodedText)
print(f"Decoded Text:\n{strDecodedText}")
print(f"\nNumber of times decoded: {intDecodingCount}")
## ------- end of script ----- ### 
