cmake_minimum_required(VERSION 3.10)
project(ELFAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include ELFIO
add_subdirectory(ELFIO)

# Add main source files
add_executable(elf_analyzer
    main.cpp
    analyzer/StaticAnalyzer.cpp
)

# Include directories
target_include_directories(elf_analyzer PRIVATE
    ${CMAKE_SOURCE_DIR}/ELFIO
    ${CMAKE_SOURCE_DIR}/analyzer
)

# Link against ELFIO (header-only library)
target_link_libraries(elf_analyzer elfio)