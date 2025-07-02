# ELFAnalyzer

ELFAnalyzer is a tool designed for static analysis of ELF (Executable and Linkable Format) files. The project reads and analyzes ELF binaries to extract useful information such as sections, segments, symbols, and relocation tables. It provides a console interface to display the analysis results clearly.

## Installation and Setup

To set up the ELFAnalyzer project, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd ELFAnalyzer
   ```

2. **Install CMake:**
   If you don't have CMake installed, download and install it from [CMake's official website](https://cmake.org/download/).

3. **Build the Project:**
   Create a build directory and compile the project:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

## Usage

After successfully building the project, you can analyze an ELF binary by executing the following command in your terminal:

```bash
./elf_analyzer <ELF binary>
```

Replace `<ELF binary>` with the path to the ELF file you want to analyze. The tool will output various information such as:

- ELF Class (32-bit or 64-bit)
- Entry Point
- Sections (type, flags, address, and size)
- Segments (type, flags, virtual and physical addresses, file size, memory size)
- Symbols (name, value, size, binding type, and associated section)
- Relocation tables

## Dependencies

- **CMake**: Minimum version 3.10
- **ELFIO**: The project uses the ELFIO library for reading ELF files. The library is included as a subdirectory in the project.

## Additional Information

- Ensure your ELF files are accessible and valid.
- The analysis results may vary based on the structure of the ELF binary being analyzed.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- This project utilizes the ELFIO library. For more information about ELF files, see the [ELF documentation](https://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/docs/elf.pdf).