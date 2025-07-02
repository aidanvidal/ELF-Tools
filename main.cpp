#include <iostream>
#include "StaticAnalyzer.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <ELF binary>" << std::endl;
        return 1;
    }

    const std::string elfFilePath = argv[1];
    StaticAnalyzer analyzer;

    if (!analyzer.loadELF(elfFilePath)) {
        std::cerr << "Failed to parse ELF file: " << elfFilePath << std::endl;
        return 1;
    }

    analyzer.runChecks();

    return 0;
}