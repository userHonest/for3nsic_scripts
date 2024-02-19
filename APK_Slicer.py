#!/usr/bin/env python3
#------------------------------------------------------#
#	Program Description: APK Slicer
#	Author: userHonest
#	Date: 02/11/23
#------------------------------------------------------#

import os
import subprocess
import subprocess
import sys
import re
from tabulate import tabulate
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors



def fnExtractApk(strApkPath, strOutputDir):
	try:
		subprocess.run(['apktool', 'd', strApkPath, '-o', strOutputDir], check=True)
	except subprocess.CalledProcessError:
		print("Error while extracting APK. Make sure apktool is installed and the APK file path is correct.")
		exit(1)


def lstScanForHttp(strOutputDir):
	dctHttpMatches = {}
    
	for strRoot, lstDirs, lstFiles in os.walk(strOutputDir):
		for strFile in lstFiles:
			if strFile.endswith('.smali'):  # Focus on smali (compiled Java) files
				strFilepath = os.path.join(strRoot, strFile)
				with open(strFilepath, 'r', errors='replace') as objFile:
					lstLines = objFile.readlines()
					for intIndex, strLine in enumerate(lstLines):
						lstMatches = re.findall(r'http://\S+', strLine)
						if lstMatches:
                            # Store the file, line number, and a few surrounding lines for context
							intStart = max(intIndex - 2, 0)
							intEnd = min(intIndex + 3, len(lstLines))
							strContext = "".join(lstLines[intStart:intEnd])
                            
							if strFilepath not in dctHttpMatches:
								dctHttpMatches[strFilepath] = []
							dctHttpMatches[strFilepath].append((intIndex + 1, strContext))
    
	return dctHttpMatches

def generate_report(dctHttpMatches, filename='report.pdf'):
	doc = SimpleDocTemplate(filename, pagesize=landscape(letter), rightMargin=30, leftMargin=30,topMargin=30,bottomMargin=18)
	story = []

    # Create the table data
	table_data = [['File Path', 'Line Number', 'Context']]
	for strFilepath, lstDetails in dctHttpMatches.items():
		for intLineNo, strContext in lstDetails:

			truncated_context = strContext.strip() if len (strContext.strip()) < 500 else strContext.strip()[:500] + "..."
			table_data.append([strFilepath, intLineNo, strContext.strip()])

    # Create the table and set its style

	column_widths = [3*inch, 0.75*inch, 4.25*inch]

	report_table = Table(table_data, colWidths=column_widths)

	report_table.setStyle(TableStyle([
		('BACKGROUND', (0, 0), (-1, 0), colors.grey),
		('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
		('ALIGN', (0, 0), (-1, -1), 'CENTER'),
		('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
		('FONTSIZE', (0, 0), (-1, 0), 10), ## font size 
		('BOTTOMPADDING', (0, 0), (-1, 0), 12),
		('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
		('GRID', (0, 0), (-1, -1), 1, colors.black),
		('VALIGN', (0,0), (-1,-1), 'TOP'),
		('WORDWRAP', (0,0), (-1,-1), 'CJK'),
	]))

	story.append(report_table)
	doc.build(story)

	print(f"Report saved as {filename}")



def main():
	

	if len(sys.argv) != 2:
		print("Usage: python scan_apk.py <path_to_apk>")
		exit(1)

	strApkPath = sys.argv[1]
	strOutputDir = "decoded_apk"
    
	# Extract the APK
	print(f"Decoding {strApkPath}...")
	fnExtractApk(strApkPath, strOutputDir)
    
    # Scan for HTTP
	print("Scanning for HTTP URLs...")
	dctHttpMatches = lstScanForHttp(strOutputDir)
	if dctHttpMatches:
		print("\nFound HTTP URLs:")

		for strFilepath, lstDetails in dctHttpMatches.items():
			print(f"\nIn file: {strFilepath}")
			for intLineNo, strContext in lstDetails:
				print(f"At line {intLineNo}:\n{strContext}\n{'-'*40}")
	else:
		print("\nNo HTTP URLs found.")
    
    # Clean up

	generate_report(dctHttpMatches, "http_report.pdf")
	subprocess.run(['rm', '-rf', strOutputDir], check=True)


	report = generate_report(dctHttpMatches)
	print(report)

if __name__ == '__main__':
	main()

# --------- End of file --------------------------------#
