// Open bin file and print out the readable data 
//compile :  gcc ReadBinaryData.c -o Program 

#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file;
    int i, numOfIntegers;
    int *data;

    // Open the binary file for reading
    file = fopen("data.bin", "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Determine the number of integers in the file
    fseek(file, 0, SEEK_END);
    numOfIntegers = ftell(file) / sizeof(int);
    rewind(file);

    // Allocate memory to store the integers
    data = (int *) malloc(numOfIntegers * sizeof(int));
    if (data == NULL) {
        perror("Memory allocation failed");
        fclose(file);
        return 1;
    }

    // Read the integers from the binary file into the data array
    fread(data, sizeof(int), numOfIntegers, file);

    // Close the binary file
    fclose(file);

    // Print the integers
    for (i = 0; i < numOfIntegers; i++) {
        printf("%d\n", data[i]);
    }

    // Free the allocated memory
    free(data);

    return 0;
}
