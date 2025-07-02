#include "StaticAnalyzer.h"
#include <iostream>
#include <string>
#include <unordered_map>

// Helpful document for understanding what ELF is: https://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/docs/elf.pdf

bool StaticAnalyzer::loadELF(const std::string &path)
{
    return reader.load(path);
}

void StaticAnalyzer::runChecks()
{
    std::cout << "Analyzing ELF file...\n";
    std::cout << "ELF Class: " << (reader.get_class() == ELFIO::ELFCLASS64 ? "64-bit" : "32-bit") << "\n";
    std::cout << "Entry Point: 0x" << std::hex << reader.get_entry() << "\n";
    listSections();
    listSegments();
    listSymbols();
    // listStringTables();
    listRelocationTables();
}

void StaticAnalyzer::listSections()
{

    // Talks used to convert section types and flags to string
    std::unordered_map<unsigned int, std::string> type_map = {
        {ELFIO::SHT_NULL, "NULL"},
        {ELFIO::SHT_PROGBITS, "PROGBITS"},
        {ELFIO::SHT_SYMTAB, "SYMTAB"},
        {ELFIO::SHT_STRTAB, "STRTAB"},
        {ELFIO::SHT_RELA, "RELA"},
        {ELFIO::SHT_HASH, "HASH"},
        {ELFIO::SHT_DYNAMIC, "DYNAMIC"},
        {ELFIO::SHT_NOTE, "NOTE"},
        {ELFIO::SHT_NOBITS, "NOBITS"},
        {ELFIO::SHT_REL, "REL"},
        {ELFIO::SHT_SHLIB, "SHLIB"},
        {ELFIO::SHT_DYNSYM, "DYNSYM"}};

    std::unordered_map<unsigned int, std::string> flags_map = {
        {ELFIO::SHF_WRITE, "WRITE"},
        {ELFIO::SHF_ALLOC, "ALLOC"},
        {ELFIO::SHF_EXECINSTR, "EXECINSTR"},
        {ELFIO::SHF_MERGE, "MERGE"},
        {ELFIO::SHF_STRINGS, "STRINGS"},
        {ELFIO::SHF_INFO_LINK, "INFO_LINK"},
        {ELFIO::SHF_LINK_ORDER, "LINK_ORDER"},
        {ELFIO::SHF_OS_NONCONFORMING, "OS_NONCONFORMING"},
        {ELFIO::SHF_GROUP, "GROUP"},
        {ELFIO::SHF_TLS, "TLS"},
        {ELFIO::SHF_COMPRESSED, "COMPRESSED"},
        {ELFIO::SHF_MASKOS, "MASKOS"},
        {ELFIO::SHF_MASKPROC, "MASKPROC"},
    };

    std::cout << "Listing sections...\n";
    for (const auto &section : reader.sections)
    {
        std::cout << "Section: " << section->get_name()
                  << ", Type: " << type_map[section->get_type()]
                  << ", Flags: " << flags_map[section->get_flags()]
                  << ", Address: 0x" << std::hex << section->get_address()
                  << ", Size: " << section->get_size() << "\n";
    }
}

void StaticAnalyzer::listSegments()
{
    std::cout << "Listing segments...\n";
    for (const auto &segment : reader.segments)
    {
        std::cout << "Segment Type: " << segment->get_type()
                  << ", Flags: " << segment->get_flags()
                  << ", Virtual Address: 0x" << std::hex << segment->get_virtual_address()
                  << ", Physical Address: 0x" << segment->get_physical_address()
                  << ", File Size: " << segment->get_file_size()
                  << ", Memory Size: " << segment->get_memory_size() << "\n";
    }
}

void StaticAnalyzer::listSymbols()
{

    // Tables used to convert symbol binding and type to string
    std::unordered_map<unsigned char, std::string> bind_map = {
        {ELFIO::STB_LOCAL, "LOCAL"},
        {ELFIO::STB_GLOBAL, "GLOBAL"},
        {ELFIO::STB_WEAK, "WEAK"},
        {ELFIO::STB_LOPROC, "LOPROC"},
        {ELFIO::STB_HIPROC, "HIPROC"}};
    std::unordered_map<unsigned char, std::string> type_map = {
        {ELFIO::STT_NOTYPE, "NOTYPE"},
        {ELFIO::STT_OBJECT, "OBJECT"},
        {ELFIO::STT_FUNC, "FUNC"},
        {ELFIO::STT_SECTION, "SECTION"},
        {ELFIO::STT_FILE, "FILE"},
        {ELFIO::STT_LOPROC, "LOPROC"},
        {ELFIO::STT_HIPROC, "HIPROC"}};

    std::cout << "Listing symbols...\n";

    // Loop through all sections
    ELFIO::Elf_Half sec_num = reader.sections.size();
    for (int i = 0; i < sec_num; ++i)
    {
        ELFIO::section *sec = reader.sections[i];
        // If the section is a symbol table
        if (sec->get_type() == ELFIO::SHT_SYMTAB || sec->get_type() == ELFIO::SHT_DYNSYM)
        {
            std::cout << "Section: " << sec->get_name()
                      << ", Type: " << (sec->get_type() == ELFIO::SHT_SYMTAB ? "SYMTAB" : "DYNSYM")
                      << ", Size: " << sec->get_size()
                      << ", Entry Size: " << sec->get_entry_size() << "\n";
            const ELFIO::symbol_section_accessor symbols(reader, sec);
            for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j)
            {
                std::string name;
                ELFIO::Elf64_Addr value;
                ELFIO::Elf_Xword size;
                unsigned char bind, type;
                ELFIO::Elf_Half section_index;
                unsigned char other;

                if (symbols.get_symbol(j, name, value, size, bind, type, section_index, other))
                {
                    std::cout << "Symbol " << j << ": " << name
                              << ", Value: 0x" << std::hex << value
                              << ", Size: " << size
                              << ", Bind: " << bind_map[bind]
                              << ", Type: " << type_map[type]
                              << ", Section Index: " << section_index
                              << ", Other: " << static_cast<int>(other) << "\n";
                }
            }
        }
    }
}

void StaticAnalyzer::listStringTables()
{
    std::cout << "Listing string tables...\n";
    for (const auto &section : reader.sections)
    {
        if (section->get_type() == ELFIO::SHT_STRTAB)
        {
            std::cout << "String Table: " << section->get_name()
                      << ", Size: " << section->get_size() << "\n";
            const char *data = section->get_data();
            for (size_t i = 0; i < section->get_size(); ++i)
            {
                if (data[i] == '\0')
                {
                    // Print the string starting at the last null terminator (or start)
                    static size_t last = 0;
                    if (i > last)
                    {
                        std::string str(&data[last]);
                        if (!str.empty())
                            std::cout << "String: \"" << str << "\" at offset " << last << "\n";
                    }
                    last = i + 1;
                }
            }
        }
    }
}

void StaticAnalyzer::listRelocationTables()
{
    std::cout << "Listing relocation tables...\n";
    // Loop through all sections
    ELFIO::Elf_Half sec_num = reader.sections.size();
    for (int i = 0; i < sec_num; ++i)
    {
        ELFIO::section *sec = reader.sections[i];
        // If the section is a relocation table
        if (sec->get_type() == ELFIO::SHT_REL || sec->get_type() == ELFIO::SHT_RELA)
        {
            std::cout << "Section: " << sec->get_name()
                      << ", Type: " << (sec->get_type() == ELFIO::SHT_REL ? "REL" : "RELA")
                      << ", Size: " << sec->get_size()
                      << ", Entry Size: " << sec->get_entry_size() << "\n";
            const ELFIO::relocation_section_accessor relocations(reader, sec);
            for (unsigned int j = 0; j < relocations.get_entries_num(); ++j)
            {
                ELFIO::Elf64_Addr offset;
                ELFIO::Elf_Word type;
                ELFIO::Elf_Word symbol;
                ELFIO::Elf_Sxword addend = 0; // Only used for SHT_RELA
                if (relocations.get_entry(j, offset, type, symbol, addend))
                {
                    std::cout << "Relocation " << j << ": "
                              << "Offset: 0x" << std::hex << offset
                              << ", Type: " << type
                              << ", Symbol: " << symbol
                              << ", Addend: " << addend << "\n";
                }
            }
        }
    }
}