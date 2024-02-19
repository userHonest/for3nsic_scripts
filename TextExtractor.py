# Script to extract data hidden in the pixels. Extracting the LSB to reconstruct the binary representation of some hidden data.
# usage : python3 script.py image.png

from PIL import Image
import sys


def pixel(img, ext, pix):
    for h in range(0, img.height):
        for w in range(0, img.width):
            r, g, b = pix[w, h]
            #shift r, g, b by 7 bits
            red = r >> 7
            green = g >> 7
            blue = b >> 7
            ext += str(red)
            ext += str(green)
            ext += str(blue)
    return ext

def main(): 

    #Syntax: python3 bits.py filename.png
    filename = sys.argv[-1:][0]

    with Image.open(filename, 'r') as img:
        ext = ''
        pix = img.load()
        ext = pixel(img, ext, pix)
        p = len(ext)//8
        ch = []
        for i in range(p):
            a = 8*i
            b = 8*(i+1)
            c = ext[a:b]
            d = chr(int(c, 2))
            ch.append(d)
        #Output will be in output.txt
        open('output.txt', 'w').write(''.join(ch))

main()
