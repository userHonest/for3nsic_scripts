// Reasembling .so (shared object) files from APK RE to Assembly code
// The .so data is all binary and unreable, so se if i can understand more the functionality of some shared object files 
// compiled as APK.

#include <iostream>
#include <fstream>
#include <vector>
#include <capstone/capstone.h>

// Function to disassemble the binary code
void disassembleBinary(const std::vector<unsigned char>& buffer) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) // Adjust CS_MODE_32 based on the binary architecture (32 or 64 bit)
        return;

    count = cs_disasm(handle, buffer.data(), buffer.size(), 0x1000, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    } else {
        std::cerr << "Failed to disassemble the binary\n";
    }

    cs_close(&handle);
}

int main(int argc, char* argv[]) {
    // Check for the correct number of arguments
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path to binary file>" << std::endl;
        return 1;
    }

    std::string filePath = argv[1];
    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
        std::cerr << "Cannot open file: " << filePath << std::endl;
        return 1;
    }

    // Read the file into a buffer
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});

    file.close();

    // Disassemble the binary
    disassembleBinary(buffer);

    return 0;
}
