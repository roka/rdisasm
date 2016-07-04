#ifndef __ELF_H__
#define __ELF_H__

#define _32BIT_ 1
#define _64BIT_ 2

#define _LITTLE_ENDIAN_ 1
#define _BIG_ENDIAN_ 2

#define X86 0X3
#define X86_64 0x3e

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

struct elf_header {
    char magic_number; //  Magic number - 0x7F
    char ascii[3]; // ELF in ASCII
    char bits; // 1 = 32bit, 2=64bit
    char endianness; // 1 = little endian, 2 = big endian
    char version; // ELF version
    char padding[8];
    uint16_t binprop; //1 = relocatable, 2 = executable, 3 = shared, 4 = core
    uint16_t arch; // 0x3 x86, 0x28 ARM, 0x3e x86_64
    uint32_t elf_ver; // ELF version
};

struct elf32 {
    uint32_t entry; // Program entry poisition
    uint32_t program_header; // Program header table position
    uint32_t section_header; // Section header table position
    uint32_t flags;
    uint16_t header_size;
    uint16_t entry_size_program;
    uint16_t num_entries_program;
    uint16_t entry_size_section;
    uint16_t num_entries_section;
    uint16_t index;
};

struct elf64 {
    uint64_t entry; // Program entry poisition
    uint64_t program_header; // Program header table position
    uint64_t section_header; // Section header table position
    uint32_t flags;
    uint16_t header_size;
    uint16_t entry_size_program;
    uint16_t num_entries_program;
    uint16_t entry_size_section;
    uint16_t num_entries_section;
    uint16_t index;
};

struct elf_header getElfHeader(FILE *file); /* Get byte 0-23 from the ELF header */
struct elf64 getElfHeader64(FILE *file); /* Get the 64 bit elf header (byte 24-63) */
struct elf32 getElfHeader32(FILE *file); /* Get the 32 bit elf header (byte 24-51)*/

#endif
