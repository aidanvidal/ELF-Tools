#pragma once
#include <string>
#include "elfio/elfio.hpp"

class StaticAnalyzer {
public:
    bool loadELF(const std::string& path);
    void runChecks();

private:
    ELFIO::elfio reader;

    void checkEntryPoint();
    void checkRWXSections();
    void checkSuspiciousStrings();
    void listSymbols();
    void listSections();
    void listSegments();
    void listStringTables();
    void listRelocationTables();
};