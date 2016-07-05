#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include "bin/elf.h"
#include "arch/x86-64.h"
#include "defines.h"

int verbose = 0;

int main(int argc, char *argv[])
{
    size_t filesize;
    FILE *infile;
    uint64_t first_asm;
    int bin_type = 0;
    int arch_type = 0;
    int c;

    /* Parse args */
    while ((c = getopt(argc, argv, "b:m:v")) != -1) {
        switch(c)
        {
            case 'b':
                if( strcmp(optarg, "elf") == 0 ) {
                    bin_type = BINARY_ELF;
                } else if ( strcmp(optarg, "raw") == 0 ) {
                    bin_type = BINARY_RAW;
                } else {
                    abort();
                }
                break;
            case 'm':
                if( strcmp(optarg, "x86-64") == 0) {
                    arch_type = ARCH_IA64;
                } else if( strcmp(optarg, "x86") == 0) {
                    arch_type = ARCH_IA32;
                }
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                abort();
                break;
        }
    }

    if( optind < argc) {
        infile = fopen(argv[optind], "rb");
    } else {
        printf("Error: No input file\n");
        abort();
    }

    fseek(infile, 0, SEEK_END);
    filesize = ftell(infile);
    rewind(infile);

    if( bin_type == BINARY_ELF || bin_type == 0) {
        struct elf_header eheader = getElfHeader(infile);
        struct elf64 eheader64 = getElfHeader64(infile);
        first_asm = eheader64.header_size + (eheader64.entry_size_program *
            eheader64.num_entries_program); // The first assembly instruction
    } else if( bin_type == BINARY_RAW ) {
        first_asm = 0x0;
    }

    if(verbose)
        printf("asm start: %lx\n", first_asm);

    char *ch = malloc(sizeof(char));
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    if( arch_type == ARCH_IA64 || arch_type == 0) {
        disasm(first_asm, infile);
    } else if( arch_type == ARCH_IA32) {
        printf("Arch x86 is not supported\n");
        abort();
    }

    fclose(infile);
    printf("\n");
    return 0;
}
