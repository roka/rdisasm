#include "elf.h"
#include "../defines.h"

/* Get byte 0-23 from the ELF header */
struct elf_header getElfHeader(FILE *file)
{
    struct elf_header *e = malloc(sizeof(struct elf_header));
    rewind(file);
    fread(e, sizeof(struct elf_header), 1, file);

    if(verbose) {
        printf("Magic number: %x\n", e->magic_number);
        printf("ASCII: %.3s\n", e->ascii);
        printf("Bits: %d\n", e->bits);
        printf("Endianness: %d\n", e->endianness);
        printf("Version: %d\n", e->version);
    }
    return *e;
}

/* Get the 64 bit elf header (byte 24-63) */
struct elf64 getElfHeader64(FILE *file)
{
    struct elf64 *e = malloc(sizeof(struct elf64));
    fread(e, sizeof(struct elf64), 1, file);
    if(verbose) {
        printf("Entry: %lx\n", e->entry);
        printf("Program header table position: %lx\n", e->program_header);
        printf("Section header table position: %lx\n", e->section_header);
        printf("Header size: %x\n", e->header_size);
        printf("Size of an entry in the program header table: %x\n", e->entry_size_program);
        printf("Number of entries in the program header table: %x\n", e->num_entries_program);
        printf("Index: %x\n", e->index);
    }

    return *e;
}

/* Get the 32 bit elf header (byte 24-51)*/
struct elf32 getElfHeader32(FILE *file)
{
    struct elf32 *e = malloc(sizeof(struct elf32));
    fread(e, sizeof(struct elf32), 1, file);
    if(verbose) {
        printf("Entry: %x\n", e->entry);
    }

    return *e;
}
