#include "x86-64.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* decode r1 and the mod bits from the 32/64 ModRM byte */
void ModRM64_r1m(char byte, FILE *file)
{
    int8_t i8;
    int32_t i32;

    if((byte & MOD3) != MOD3) {
        // decode the bits 000000111
        if( (byte & MODRM) == MODRM_RAX ) {
            printf("DWORD [rax");
        } else if( (byte & MODRM) == MODRM_RCX ) {
            printf("DWORD [rcx");
        } else if( (byte & MODRM) == MODRM_RDX ) {
            printf("DWORD [rdx");
        } else if( (byte & MODRM) == MODRM_RBX ) {
            printf("DWORD [rbx");
        } else if( ((byte & MODRM) == MODRM_RIP) && ((byte & MOD3) == MOD0) ) {
            printf("DWORD [rip");
        } else if( ((byte & MODRM) == MODRM_RIP) && ((byte & MOD3) != MOD0) ) {
            printf("DWORD [rbp");
        } else if( (byte & MODRM) == MODRM_RSI ) {
            printf("DWORD [rsi");
        } else if( (byte & MODRM) == MODRM_RDI ) {
            printf("DWORD [rdi");
        } else if( (byte & MODRM) == MODRM_SIB ) {
            printf("TODO SIB");
        }

        // decode the bits 11000000
        if( ((byte & MODRM) == MODRM_RIP) && ((byte & MOD3) == MOD0) ) {
            fread(&i32, sizeof(int32_t), 1, file);
            printf("+0x%x]", i32);
        } else if ( ((byte & MOD3) == MOD0) ) {
            printf("]");
        } else if ( ((byte & MOD3) == MOD1) ) {
            fread(&i8, sizeof(int8_t), 1, file);
            printf("+0x%x]", i8);
        } else if ( ((byte & MOD3) == MOD2) ) {
            fread(&i32, sizeof(int32_t), 1, file);
            printf("+0x%x]", i32);
        }
    } else {
        if( (byte & MODRM) == MODRM_RAX ) {
            printf("rax");
        } else if( (byte & MODRM) == MODRM_RCX ) {
            printf("rcx");
        } else if( (byte & MODRM) == MODRM_RDX ) {
            printf("rdx");
        } else if( (byte & MODRM) == MODRM_RBX ) {
            printf("rbx");
        } else if( (byte & MODRM) == MODRM_RIP) {
            printf("rsp");
        } else if( (byte & MODRM) == MODRM_RSI ) {
            printf("rsi");
        } else if( (byte & MODRM) == MODRM_RDI ) {
            printf("rdi");
        } else if( (byte & MODRM) == MODRM_SIB ) {
            printf("rbp");
        }
    }
}

/* decode the dest in the 32/64 ModRM byte */
void ModRM64_r2(uint8_t byte, int reg)
{
    // decode the bits 00111000
    switch(reg) {
        case IA64_R8:
            printf("%s", ia64_r8_without_rex[((byte&0x38) >> 3)]);
            break;
        case IA64_R16:
            printf("%s", ia64_r16[((byte&0x38) >> 3)]);
            break;
        case IA64_R32:
            printf("%s", ia64_r32[((byte&0x38) >> 3)]);
            break;
        case IA64_R64:
            printf("%s", ia64_r64[((byte&0x38) >> 3)]);
            break;
    }
}

/* Dissassemble the 32/64bit ModR/M byte
   http://ref.x86asm.net/coder64.html#modrm_byte_32_64
*/
void ModRM64(char byte, FILE *file)
{
  ModRM64_r2(byte, IA64_R8);
  ModRM64_r1m(byte, file);
}

/* r/m8, r8 */
__inline rm8_r8(FILE *file)
{
    uint8_t byte;
    fread(&byte, sizeof(uint8_t), 1, file);
    ModRM64_r1m(byte, file);
    printf(", ");
    ModRM64_r2(byte, IA64_R8);
}

/* r8, r/m8 */
__inline r8_rm8(FILE *file)
{
    uint8_t byte;
    fread(&byte, sizeof(uint8_t), 1, file);
    ModRM64_r2(byte, IA64_R8);
    printf(", ");
    ModRM64_r1m(byte, file);
}

/* r/m16/32/64, r/16/32/64 */
__inline rm163264_r163264(FILE *file, uint8_t rex)
{
    uint8_t byte;
    fread(&byte, sizeof(uint8_t), 1, file);
    if( (rex >> REX_W) & 1 ) { // check if 64bit operand
        if(rex >> REX_B & 1 ) { // new registers
            ModRM64_r1m(byte, file);
            printf(", ");
            ModRM64_r2(byte, IA64_R64);
        } else {
            ModRM64_r1m(byte, file);
            printf(", ");
            ModRM64_r2(byte, IA64_R64);
        }
    } else {
        if(rex >> REX_B & 1 ) { // new registers
            ModRM64_r1m(byte, file);
            printf(", ");
            ModRM64_r2(byte, IA64_R32);
        } else {
            ModRM64_r1m(byte, file);
            printf(", ");
            ModRM64_r2(byte, IA64_R32);
        }
    }
}

/*  r/16/32/64, r/m16/32/64 */
__inline r163264_rm163264(FILE *file, uint8_t rex)
{
    uint8_t byte;
    fread(&byte, sizeof(uint8_t), 1, file);
    if( (rex >> REX_W) & 1 ) { // check if 64bit operand
        if(rex >> REX_B & 1 ) { // new registers
            ModRM64_r2(byte, IA64_R64);
            printf(", ");
            ModRM64_r1m(byte, file);
        } else {
            ModRM64_r2(byte, IA64_R64);
            printf(", ");
            ModRM64_r1m(byte, file);
        }
    } else {
        if(rex >> REX_B & 1 ) { // new registers
            ModRM64_r2(byte, IA64_R32);
            printf(", ");
            ModRM64_r1m(byte, file);
        } else {
            ModRM64_r2(byte, IA64_R32);
            printf(", ");
            ModRM64_r1m(byte, file);
        }
    }
}

__inline al_imm8(FILE *file)
{
    uint8_t u8;
    fread(&u8, sizeof(uint8_t), 1, file);
    printf("al, 0x%.2x", u8 & 0xff);
}

__inline eax_imm1632(FILE *file)
{
    uint32_t u32;
    fread(&u32, sizeof(uint32_t), 1, file);
    printf("eax, 0x%x", u32);
}

__inline imm1632(FILE *file)
{
    uint32_t u32;
    fread(&u32, sizeof(uint32_t), 1, file);
    printf("dword 0x%x", u32);
}

__inline imm8(FILE *file)
{
    uint32_t u8;
    fread(&u8, sizeof(uint8_t), 1, file);
    printf("byte 0x%x", u8 & 0xff);
}


/* Check for segment override. returns 1 if found */
int segmentOverride(char byte)
{
  if(byte == CS_OVERRIDE) {
    printf("cs ");
    return 1;
  } else if(byte == SS_OVERRIDE) {
    printf("ss ");
    return 1;
  } else if(byte == DS_OVERRIDE) {
    printf("ds ");
    return 1;
  } else if(byte == ES_OVERRIDE) {
    printf("es ");
    return 1;
  } else if(byte == FS_OVERRIDE) {
    printf("fs ");
    return 1;
  } else if(byte == GS_OVERRIDE) {
    printf("gs ");
    return 1;
  }
  return 0;
}

/* Check for instruction prefix, return 1 if found */
int instructionPrefix(char byte) {
  if(byte == LOCK) {
    printf("lock ");
    return 1;
  } else if(byte == REPNE) {
    printf("repnz ");
    return 1;
  } else if(byte == REP) {
    printf("repz ");
    return 1;
  }
  return 0;
}

/* Check for operand size override return 1 if found */
int operandOverride(char byte)
{
  if(byte == OPERAND_SIZE_OVERRIDE) {
    printf("addr32 ");
    return 1;
  }
  return 0;
}

/* Check for address size override, return 1 if found */
int addressOverride(char byte)
{
  if(byte == ADDRESS_SIZE_OVERRIDE) {
    printf("data16 ");
    return 1;
  }
  return 0;
}

/* Pattern used to decode most instructions between 0x00 - 0x3d */
__inline pattern1(uint8_t u8, FILE *file, uint8_t rex)
{
    switch( (u8&0xff) ) {
        case 0:
            rm8_r8(file); break;
        case 1:
            rm163264_r163264(file, rex); break;
        case 2:
            r8_rm8(file); break;
        case 3:
            r163264_rm163264(file, rex); break;
        case 4:
            al_imm8(file); break;
        case 5:
            eax_imm1632(file); break;
    }
    printf("\n");
}

void disasm(uint64_t first_asm, FILE *file)
{
    /* Variables used to store read data */
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    int16_t i8;
    int16_t i16;
    int32_t i32;
    int64_t i64;

    uint8_t rex;

    rewind(file);
    fseek(file, first_asm, SEEK_SET); // seek to the first assembly instruction

    while( fread(&u8, sizeof(uint8_t), 1, file) == 1) {
        /* Check Prefixes and Overrides */
        if( instructionPrefix(u8) == 1) {
            continue;
        } else if(segmentOverride(u8) == 1 ) {
            continue;
        } else if(operandOverride(u8) == 1 ) {
            continue;
        } else if(addressOverride(u8) == 1 ) {
            continue;
        }

        /* ADD - 0x00 - 0x05 */
        else if( u8 >= ADD_00 && u8 <= ADD_05 ) {
            printf("ADD\t");
            pattern1(u8-ADD_00, file, rex);
        }

        /* OR - Logical inclusive OR 0x08-0d */
        else if( u8 >= OR_08 && u8 <= OR_0d ) {
            printf("OR\t");
            pattern1(u8-OR_08, file, rex);
        }

        /* ADC - Add with cary 0x10-0x15 */
        else if( u8 >= ADC_10 && u8 <= ADC_15 ) {
            printf("ADC\t");
            pattern1(u8-ADC_10, file, rex);
        }

        /* SBB - Subtraction with borrow 0x18-0x1d */
        else if( u8 >= SBB_18 && u8 <= SBB_1d ) {
            printf("sbb\t");
            pattern1(u8-SBB_18, file, rex);
        }

        /* Logical AND 0x20-0x25 */
        else if( u8 >= AND_20 && u8 <= AND_25 ) {
            printf("and\t");
            pattern1(u8-AND_20, file, rex);
        }

        /* Subtraction 0x28-0x2d */
        else if( u8 >= SUB_28 && u8 <= SUB_2d ) {
            printf("sub\t");
            pattern1(u8-SUB_28, file, rex);
        }

        /* Logical exclusive OR - 0x30 - 0x35 */
        else if( u8 >= XOR_30 && u8 <= XOR_35 ) {
            printf("xor\t");
            pattern1(u8-XOR_30, file, rex);
        }

        /* Compare two operands 0x38-0x3d */
        else if( u8 >= CMP_38 && u8 <= 0x3d ) {
            printf("cmp\t");
            pattern1(u8-CMP_38, file, rex);
        }

        /* REX 0x40-0x4f */
        else if( u8 == REX_40 ) {
            rex |= 1 << REX;
            continue;
        } else if( u8 == REXB_41 ) {
            rex |= 1 << REX_B;
            continue;
        } else if( u8 == REXX_42 ) {
            rex |= 1 << REX_X;
            continue;
        } else if( u8 == REXXB_43 ) {
            rex |= 1 << REX_X;
            rex |= 1 << REX_B;
            continue;
        } else if( u8 == REXR_44 ) {
            rex |= 1 << REX_R;
            continue;
        } else if( u8 == REXRB_45 ) {
            rex |= 1 << REX_R;
            rex |= 1 >> REX_B;
            continue;
        } else if( u8 == REXRX_46 ) {
            rex |= 1 << REX_R;
            rex |= 1 >> REX_X;
            continue;
        } else if( u8 == REXRXB_47 ) {
            rex |= 1 << REX_R;
            rex |= 1 >> REX_X;
            rex |= 1 >> REX_B;
            continue;
        } else if( u8 == REXW_48 ) {
            rex |= 1 << REX_W;
            continue;
        } else if( u8 == REXWB_49 ) {
            rex |= 1 << REX_W;
            rex |= 1 << REX_B;
            continue;
        } else if( u8 == REXWX_4a ) {
            rex |= 1 << REX_W;
            rex |= 1 << REX_X;
            continue;
        } else if( u8 == REXWXB_4b ) {
            rex |= 1 << REX_W;
            rex |= 1 << REX_X;
            rex |= 1 << REX_B;
            continue;
        } else if( u8 == REXWR_4c ) {
            rex |= 1 << REX_W;
            rex |= 1 << REX_R;
            continue;
        } else if( u8 == REXWRB_4d ) {
            rex |= 1 << REX_W;
            rex |= 1 << REX_R;
            rex |= 1 << REX_B;
            continue;
        } else if( u8 == REXWRX_4e ) {
            rex |= 1 << REX_W;
            rex |= 1 << REX_R;
            rex |= 1 << REX_X;
            continue;
        } else if( u8 == REXWRXB_4f ) {
            rex |= 1 << REX_W;
            rex |= 1 << REX_X;
            rex |= 1 << REX_B;
            rex |= 1 << REX_R;
            continue;
        }

        /* PUSH 0x50+r - PUSH 0x57 */
        else if( u8 >= PUSH_50 && u8 <= PUSH_57) { // TODO REX
            printf("push\t%s\n", ia64_r64[u8-PUSH_50]);
        }

        /* POP 0x58+r - POP 0x5f */
        else if( u8 >= POP_58 && u8 <= POP_5f) { // TODO REX
            printf("pop\t%s\n", ia64_r64[u8-POP_58]);
        }

        /* MOVSXD 0x63 Move with sign-extension */
        else if( u8 == MOVSXD_63 ) {
            printf("movsxd\t");
            r163264_rm163264(file, rex);
            printf("\n");
        }

        /* PUSH 0x68 imm16/32 */
        else if( u8 == PUSH_68 ) {
            printf("push\t");
            imm1632(file);
            printf("\n");
        }

        /* IMUL - 0x69 */
        else if( u8 == IMUL_69 ) {
            printf("imul\t");
            r163264_rm163264(file, rex);
            printf(", ");
            imm1632(file);
            printf("\n");
        }

        else if( u8 == PUSH_6a ) {
            printf("push\t");
            imm8(file);
            printf("\n");
        }

        else if( u8 == IMUL_6b ) {
            printf("imul\t");
            r163264_rm163264(file, rex);
            printf(", ");
            imm8(file);
            printf("\n");
        }

        else if( u8 == INSB_6c ) {
            printf("insb\tbyte [rdi], dx\n");
        } else if( u8 == INSD_6d ) {
            printf("insd\tdword [rdi], dx\n");
        } else if( u8 == OUTSB_6e ) {
            printf("outsb\tdx, byte [rsi]\n");
        } else if( u8 == OUTSD_6f ) {
            printf("outsd\tdx, dword [rsi]\n");
        }

        else if( u8 >= JO_70 && u8 <= JNLE_7f ) {
            switch(u8) {
                case JO_70: printf("JO\t"); break;
                case JNO_71: printf("JNO\t"); break;
                case JB_72: printf("JB\t"); break;
                case JNB_73: printf("JNB\t"); break;
                case JZ_74: printf("JZ\t"); break;
                case JNZ_75: printf("JNZ\t"); break;
                case JBE_76: printf("JBE\t"); break;
                case JNBE_77: printf("JNBE\t"); break;
                case JS_78: printf("JS\t"); break;
                case JNS_79: printf("JNS\t"); break;
                case JP_7a: printf("JP\t"); break;
                case JNP_7b: printf("JNP\t"); break;
                case JL_7c: printf("JL\t"); break;
                case JNL_7d: printf("JNL\t"); break;
                case JLE_7e: printf("JLE\t"); break;
                case JNLE_7f: printf("JNLE\t"); break;
            }
            fread(&u8, sizeof(uint8_t), 1, file);
            printf("0x%x\n", ((ftell(file)+u8&0xff)-first_asm));
        }

        else if( u8 == 0x80 ) {
            fread(&u8, sizeof(uint8_t), 1, file);
            if( u8 < 0x40) {
                if( u8 >= 0x00 && u8 <= 0x07 )
                    printf("add\t");
                else if( u8 >= 0x08 && u8 <= 0x0f )
                    printf("or\t");
                else if( u8 >= 0x10 && u8 <= 0x17 )
                    printf("adc\t");
                else if( u8 >= 0x18 && u8 <= 0x1f )
                    printf("sbb\t");
                else if( u8 >= 0x20 && u8 <= 0x27 )
                    printf("and\t");
                else if( u8 >= 0x28 && u8 <= 0x2f )
                    printf("sub\t");
                else if( u8 >= 0x30 && u8 <= 0x37 )
                    printf("xor\t");
                else if( u8 >= 0x38 && u8 <= 0x3f )
                    printf("cmp\t");
                ModRM64_r1m(u8, file);
                printf(", ");
                imm8(file);
                printf("\n");
            }
        }
        /* B8+r MOV imm16/32/64 */
        else if( u8 >= MOV_RAX_B8  && u8 <= MOV_RDI_B8) {
            if( (rex >> REX_W) & 1 ) { // check if 64bit operand
                fread( &u64, sizeof(uint64_t), 1, file);
                if(rex >> REX_B & 1 ) // new registers
                    printf("mov\t%s, 0x%lx\n", regs64_rex[(u8-MOV_RAX_B8)], u64);
                else
                    printf("mov\t%s, 0x%lx\n", regs64[(u8-MOV_RAX_B8)], u64);
            } else {
                fread( &u32, sizeof(uint32_t), 1, file);
                if(rex >> REX_B & 1 ) // new registers
                    printf("mov\t%s, 0x%x\n", regs32_rex[(u8-MOV_RAX_B8)], u32);
                else
                    printf("mov\t%s, 0x%x\n", regs32[(u8-MOV_RAX_B8)], u32);
            }
        }

        /*else if ( u8 == 0x00) {
            continue;
        }*/
        else {
            printf("%.2x ", u8&0xff);
        }
        rex = 0;
    }

}
