#ifndef __IA64_H__
#define __IA64_H__

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

#define BUF_SIZE 512

void ia64_disasm(uint64_t start, uint64_t end, FILE *file);


#endif
