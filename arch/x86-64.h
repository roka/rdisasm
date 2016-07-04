#ifndef __X86_64_H__
#define __X86_64_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/* Instruction prefix codes */
#define LOCK  0xF0
#define REPNE 0xF2 // REPNE/REPNZ
#define REP   0xF3 // REP/REPE/REPZ

/* Segment override prefixes*/
#define CS_OVERRIDE 0x2e
#define SS_OVERRIDE 0x36
#define DS_OVERRIDE 0x3e
#define ES_OVERRIDE 0x26
#define FS_OVERRIDE 0x64
#define GS_OVERRIDE 0x65
#define OPERAND_SIZE_OVERRIDE 0x66
#define ADDRESS_SIZE_OVERRIDE 0x67

/* 32/64-bit ModR/M Byte */
#define MODRM     0x07
#define MODRM_RAX 0x00
#define MODRM_RCX 0x01
#define MODRM_RDX 0x02
#define MODRM_RBX 0x03
#define MODRM_SIB 0x04
#define MODRM_RIP 0x05 // RBP
#define MODRM_RSI 0x06
#define MODRM_RDI 0x07

#define R64_RAX 0x00
#define R64_RCX 0x08
#define R64_RDX 0x10
#define R64_RBX 0x18
#define R64_RSP 0x20
#define R64_RBP 0x28
#define R64_RSI 0x30
#define R64_RDI 0x38

#define MOD0 0x00
#define MOD1 0x40
#define MOD2 0x80
#define MOD3 0xc0

#define R8_REX  1
#define R8      2
#define R16     3
#define R32     4
#define R64     5
#define MM      6
#define XMM     7
#define SRED    8
#define EEE1    9
#define EEE2    10

/* REX bits */
#define REX     0
#define REX_B   1
#define REX_X   2
#define REX_R   3
#define REX_W   4

/* OPCODES http://ref.x86asm.net/coder64.html */
#define EXTENDED_OPCODE 0X0F

#define ADD_00  0x00    // r/m8, r8
#define ADD_01  0x01    // r/m16/32/64, r/16/32/64
#define ADD_02  0x02    // r8, r/m8
#define ADD_03  0x03    // r16/32/64, r/m16/32/64
#define ADD_04  0x04    // AL. imm8
#define ADD_05  0x05    // rAX, imm16/32

#define OR_08  0x08     // r/m8, r8
#define OR_09  0x09     // r/m16/32/64, r/16/32/64
#define OR_0a  0x0a     // r8, r/m8
#define OR_0b  0x0b     // r16/32/64, r/m16/32/64
#define OR_0c  0x0c     // AL. imm8
#define OR_0d  0x0d     // rAX, imm16/32

// Add with carry
#define ADC_10  0x10    // r8/m8, r8
#define ADC_11  0x11    // r/m16/32/64, r16/32/64
#define ADC_12  0x12    // r8, r/m8
#define ADC_13  0x13    // r16/32/64, r/m16/32/64
#define ADC_14  0x14    // AL. imm8
#define ADC_15  0x15    // rAX, imm16/32

// Subtraction with borrow
#define SBB_18  0x18
#define SBB_1d  0x1d

// Logical AND
#define AND_20  0x20
#define AND_25  0x25

// Subtraction
#define SUB_28  0x28
#define SUB_2d  0x2d

// Logical exclusive OR
#define XOR_30  0x30
#define XOR_35  0x35

// Compare two operands
#define CMP_38  0x38
#define CMP_3d  0x3d

#define REX_40      0x40    // Access to new 8-bit registers
#define REXB_41     0x41    // Extension of r/m field, base field, or opcode reg field
#define REXX_42     0x42    // Extension of SIB index field
#define REXXB_43    0x43    // REX.X and REX.B combination
#define REXR_44     0x44    // Extension of ModR/M reg field
#define REXRB_45    0x45    // REX.R and REX.B combination
#define REXRX_46    0x45    // REX.R and REX.X combination
#define REXRXB_47   0x47    // REX.R, REX.X and REX.B combination
#define REXW_48     0x48    // 64 Bit Operand Size
#define REXWB_49    0x49    // REX.W and REX.B combination
#define REXWX_4a    0x4a    // REX.W and REX.X combination
#define REXWXB_4b   0x4b    // REX.W, REX.X and REX.B combination
#define REXWR_4c    0x4c    // REX.W and REX.R combination
#define REXWRB_4d   0x4d    // REX.W, REX.R and REX.B combination
#define REXWRX_4e   0x4e    // REX.W, REX.R and REX.X combination
#define REXWRXB_4f  0x4f    // REX.W, REX.R, REX.X and REX.B combination

#define PUSH_50     0x50    // 50+r
#define PUSH_57     0x57

#define POP_58      0x58    // 58+r
#define POP_5f      0x5f

#define MOVSXD_63   0x63    // r32/64, R/m32 Move with sign-extension

#define PUSH_68     0x68    // imm16/32

#define IMUL_69     0x69    // signed mul
#define INSB_6c     0x6C    // Input from Port to String
#define JS_78       0x78

/* B8+r MOV imm16/32/64 */
#define MOV_RAX_B8  0xb8
#define MOV_RCX_B8  0xb9
#define MOV_RDX_B8  0xba
#define MOV_RBX_B8  0xbb
#define MOV_RSP_B8  0xbc
#define MOV_RBP_B8  0xbd
#define MOV_RSI_B8  0xbe
#define MOV_RDI_B8  0xbf

void ModRM64(char byte, FILE *file); /* Dissassemble the 32/64bit ModR/M byte */
void ModRM64_r1m(char byte, FILE *file); /* decode r1 and the mod bits from the 32/64 ModRM byte */
void ModRM64_r2(uint8_t byte, int reg); /* decode the dest in the ModRM 32/64 byte */
int segmentOverride(char byte); /* Check for segment override */
int instructionPrefix(char byte); /* Check for instruction prefix */
int operandOverride(char byte); /* Check for operand overrider */
int addressOverride(char byte); /* Check for address override */
void disasm(uint64_t first_asm, FILE *file); /* Dissassemble code starting at first_asm */

#define IA64_R8     0
#define IA64_R16    1
#define IA64_R32    2
#define IA64_R64    3

static char *ia64_r8_without_rex[] =
    { "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH" };
static char *ia64_r8_withany_rex[] =
    { "AL", "CL", "DL", "BL", "AH", "SPL", "BPL", "DIL" };
static char *ia64_r8_rex_r1[] = // REX.R = 1
    { "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
static char *ia64_r16[] =
    { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
static char *ia64_r16_rex[] = // REX.R = 1
    { "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
static char *ia64_r32[] =
    { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
static char *ia64_r32_rex[] = // REX.R = 1
    { "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
static char *ia64_r64[] =
    {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" };
static char *ia64_r64_rex[] = // REX.R = 1
    {"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

static char *regs32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
static char *regs32_rex[] = {"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
static char *regs64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
static char *regs64_rex[] = {"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};

#endif
