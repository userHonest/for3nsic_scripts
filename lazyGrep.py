import csv

# File path
csv_file_path = 'purview.csv'

# List of keywords to search for
keywords = [
    
]

# Open the CSV file and search for keywords
with open(csv_file_path, 'r') as file:
    reader = csv.reader(file)
    
    # For each row in the CSV file
    for row in reader:
        # Convert the row into a single string
        line = ', '.join(row)
        
        # Check if any keyword from the list is in the line
        for keyword in keywords:
            if keyword in line:
                print(line)
                break  # To prevent printing the same line multiple times if there are multiple keywords

## --- end of file ---##
