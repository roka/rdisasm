#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "ia64_optable.h"
#include "ia64_regs.h"
#include "ia64.h"

/* Decode the bits 11000111 in the ModRM 32/64 Byte */
int ia64_rm_163264(uint8_t byte, FILE *file, int mode, char *instr_str)
{
    int8_t i8;
    int32_t i32;

    if((byte & MOD3) != MOD3) {
        // decode the bits 000000111
        if( (byte & MODRM) == MODRM_RAX ) {
            sprintf(instr_str+strlen(instr_str), "dword [%s", ia64_regtab[mode].r1);
        } else if( (byte & MODRM) == MODRM_RCX ) {
            sprintf(instr_str+strlen(instr_str), "dword [%s", ia64_regtab[mode].r2);
        } else if( (byte & MODRM) == MODRM_RDX ) {
            sprintf(instr_str+strlen(instr_str), "dword [%s", ia64_regtab[mode].r3);
        } else if( (byte & MODRM) == MODRM_RBX ) {
            sprintf(instr_str+strlen(instr_str), "dword [%s", ia64_regtab[mode].r4);
        } else if( ((byte & MODRM) == MODRM_RIP) && ((byte & MOD3) == MOD0) ) {
            //printf("DWORD [rip");
            //sprintf(instr_str+strlen(instr_str), "DWORD [%s", ia64_regtab[mode].r1);
            sprintf(instr_str+strlen(instr_str), "dword [rip");
        } else if( ((byte & MODRM) == MODRM_RIP) && ((byte & MOD3) != MOD0) ) {
            sprintf(instr_str+strlen(instr_str), "dword [%s", ia64_regtab[mode].r6);
        } else if( (byte & MODRM) == MODRM_RSI ) {
            sprintf(instr_str+strlen(instr_str), "dword [%s", ia64_regtab[mode].r7);
        } else if( (byte & MODRM) == MODRM_RDI ) {
            sprintf(instr_str+strlen(instr_str), "dword [%s", ia64_regtab[mode].r8);
        } else if( (byte & MODRM) == MODRM_SIB ) {
            sprintf(instr_str+strlen(instr_str), "TODO SIB");
        }

        // decode the bits 11000000
        if( ((byte & MODRM) == MODRM_RIP) && ((byte & MOD3) == MOD0) ) {
            fread(&i32, sizeof(int32_t), 1, file);
            sprintf(instr_str+strlen(instr_str), "+0x%x]", i32);
        } else if ( ((byte & MOD3) == MOD0) ) {
            sprintf(instr_str+strlen(instr_str), "]");
        } else if ( ((byte & MOD3) == MOD1) ) {
            fread(&i8, sizeof(int8_t), 1, file);
            sprintf(instr_str+strlen(instr_str), "+0x%x]", i8);
        } else if ( ((byte & MOD3) == MOD2) ) {
            fread(&i32, sizeof(int32_t), 1, file);
            sprintf(instr_str+strlen(instr_str), "+0x%x]", i32);
        }
    } else {
        if( (byte & MODRM) == MODRM_RAX ) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r1);
        } else if( (byte & MODRM) == MODRM_RCX ) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r2);
        } else if( (byte & MODRM) == MODRM_RDX ) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r3);
        } else if( (byte & MODRM) == MODRM_RBX ) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r4);
        } else if( (byte & MODRM) == MODRM_RIP) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r5);
        } else if( (byte & MODRM) == MODRM_RSI ) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r7);
        } else if( (byte & MODRM) == MODRM_RDI ) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r8);
        } else if( (byte & MODRM) == MODRM_SIB ) {
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r6);
        }
    }

    return 0;
}

/* decode the bits 00111000 in the ModRM 32/64 byte */
int ia64_r_163264(uint8_t byte, int mode, char *instr_str)
{
    switch((byte&0x38)) {
        case R64_RAX:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r1);
            break;
        case R64_RCX:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r2);
            break;
        case R64_RDX:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r3);
            break;
        case R64_RBX:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r4);
            break;
        case R64_RSP:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r5);
            break;
        case R64_RBP:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r6);
            break;
        case R64_RSI:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r7);
            break;
        case R64_RDI:
            sprintf(instr_str+strlen(instr_str), "%s", ia64_regtab[mode].r8);
            break;

    }
    return 0;
}

uint8_t imm8(FILE *file)
{
    uint8_t byte;
    fread(&byte, sizeof(uint8_t), 1, file);
    return byte;
}

uint16_t imm16(FILE *file)
{
    uint16_t word;
    fread(&word, sizeof(uint16_t), 1, file);
    return word;
}

uint32_t imm32(FILE *file)
{
    uint32_t dword;
    fread(&dword, sizeof(uint32_t), 1, file);
    return dword;
}

uint64_t imm64(FILE *file)
{
    uint64_t qword;
    fread(&qword, sizeof(uint8_t), 1, file);
    return qword;
}

/* Search for a instruction in ia64_optab, returns position or -1 if not found */
int ia64_search_inst(ia64_instruction instr)
{
    int i;
    for(i=0; i < IA64_NUM_INSTR; i++) {
        if(instr.primary_opcode == ia64_optab[i].primary_opcode &&
            instr.secondary_opcode == ia64_optab[i].secondary_opcode &&
            instr.of_prefix == ia64_optab[i].of_prefix &&
            instr.register_field == ia64_optab[i].register_field) {
                return i;
            }
    }
    return -1;
}

uint8_t calc_regfield(uint8_t u8)
{
    if( u8 < 0x40) {
        if( u8 >= 0x00 && u8 <= 0x07 )
            return 1;
        else if( u8 >= 0x08 && u8 <= 0x0f )
            return 2;
        else if( u8 >= 0x10 && u8 <= 0x17 )
            return 3;
        else if( u8 >= 0x18 && u8 <= 0x1f )
            return 4;
        else if( u8 >= 0x20 && u8 <= 0x27 )
            return 5;
        else if( u8 >= 0x28 && u8 <= 0x2f )
            return 6;
        else if( u8 >= 0x30 && u8 <= 0x37 )
            return 7;
        else if( u8 >= 0x38 && u8 <= 0x3f )
            return 8;
    }
    return 0;
}

/* Disassemble x86-64 code */
void ia64_disasm(uint64_t start, uint64_t end, FILE *file)
{
    uint8_t byte=0;
    int pos;
    char instr_str[BUF_SIZE];
    int i;
    size_t rb;

    ia64_instruction instr;
    instr.primary_opcode = 0;
    instr.secondary_opcode = 0;
    instr.of_prefix = 0;
    instr.register_field = 0;
    bzero(instr_str, BUF_SIZE);

    rewind(file);
    fseek(file, start, SEEK_SET); // seek to the first assembly instruction

    for(start=start ; start < end && (rb = fread(&byte, sizeof(uint8_t), 1, file)) == 1; start++)
    {
        if(instr.primary_opcode == 0x00 && instr.of_prefix == 0x00) {
            switch(byte) {
                case 0x0f: // Two-byte instruction
                    instr.of_prefix = 0xf;
                    continue;
                case LOCK:
                    continue;
                case REPNE:
                    continue;
                case REP:
                    continue;
                case CS_OVERRIDE:
                case SS_OVERRIDE:
                case DS_OVERRIDE:
                case ES_OVERRIDE:
                case FS_OVERRIDE:
                case GS_OVERRIDE:
                    continue;
                case OPERAND_SIZE_OVERRIDE:
                    continue;
                case ADDRESS_SIZE_OVERRIDE:
                    continue;
            }
        }

        /* Read Opcodes */
        instr.primary_opcode = byte;

        pos = ia64_search_inst(instr);
        if(pos == -1) { // search instr.register_field if no instr was found
            if(fread(&byte, sizeof(uint8_t), 1, file) > 0) {
                instr.register_field = calc_regfield(byte);
                fseek(file, -1, SEEK_CUR);
                if(instr.register_field != 0)
                    pos = ia64_search_inst(instr);
            }
        }
        if( pos != -1 ) {
            sprintf(instr_str, "%s\t", ia64_optab[pos].mnemonic);

            /* get/print operands */
            for(i=0; i < 4; i++) {
                if(i > 0 && ia64_optab[pos].operand[i] != 0x00)
                    sprintf(instr_str + strlen(instr_str), ", ");
                switch( ia64_optab[pos].operand[i] ) {
                    case 0x00:
                        i=4;
                        break;
                    case __RM8:
                        if(i < 1)
                            fread(&byte, sizeof(uint8_t), 1, file);
                        ia64_rm_163264(byte, file, __MODE_R64, instr_str);
                        break;
                    case __R8:
                        if(i < 1)
                            fread(&byte, sizeof(uint8_t), 1, file);
                        ia64_r_163264(byte, __R8_WITHOUT_REX, instr_str);
                        break;
                    case __RM163264:
                        if(i < 1)
                            fread(&byte, sizeof(uint8_t), 1, file);
                        ia64_rm_163264(byte, file, __MODE_R64, instr_str);
                        break;
                    case __R163264:
                        if(i < 1)
                            fread(&byte, sizeof(uint8_t), 1, file);
                        ia64_r_163264(byte, __MODE_R32, instr_str);
                        break;
                    case __AL:
                        sprintf(instr_str + strlen(instr_str), "al");
                        break;
                    case __RAX:
                        sprintf(instr_str + strlen(instr_str), "eax");
                        break;
                    case __IMM8:
                        sprintf(instr_str + strlen(instr_str), "byte 0x%x", (imm8(file) &0xff));
                        break;
                    case __IMM1632:
                        sprintf(instr_str + strlen(instr_str), "dword 0x%x", imm32(file));
                        break;

                    case __REG_6416_1:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r1);
                        break;
                    case __REG_6416_2:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r2);
                        break;
                    case __REG_6416_3:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r3);
                        break;
                    case __REG_6416_4:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r4);
                        break;
                    case __REG_6416_5:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r5);
                        break;
                    case __REG_6416_6:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r6);
                        break;
                    case __REG_6416_7:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r7);
                        break;
                    case __REG_6416_8:
                        sprintf(instr_str + strlen(instr_str), "%s",
                            ia64_regtab[__MODE_R64].r8);
                        break;

                    case __REL_8:
                        byte = imm8(file);
                        sprintf(instr_str + strlen(instr_str),
                            "0x%x", ((ftell(file)+byte&0xff)));
                        break;
                    case __DX:
                        sprintf(instr_str + strlen(instr_str),
                            "dx");
                        break;
                    case __RSI_DWORD:
                        sprintf(instr_str + strlen(instr_str),
                            "dword [rsi]");
                        break;
                    case __RSI_BYTE:
                        sprintf(instr_str + strlen(instr_str),
                            "byte [rsi]");
                        break;
                    case __RDI_DWORD:
                        sprintf(instr_str + strlen(instr_str),
                            "dword [rdi]");
                        break;
                    case __RDI_BYTE:
                        sprintf(instr_str + strlen(instr_str),
                            "byte [rdi]");
                        break;

                }
            }
        } else {
            sprintf(instr_str, "db\t0x%x", byte&0xff);
        }

        printf("%s\n", instr_str);
        instr.primary_opcode = 0;
        instr.secondary_opcode = 0;
        instr.of_prefix = 0;
        instr.register_field = 0;
        bzero(instr_str, BUF_SIZE);
    }

}
