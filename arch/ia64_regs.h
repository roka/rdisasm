#ifndef __IA64_REGS_H__
#define __IA64_REGS_H__

#define __R8_WITHOUT_REX    0
#define __R8_WITHANY_REX    1
#define __R8_WITH_REX       2
#define __MODE_R16          3
#define __MODE_R16_REX      4
#define __MODE_R32          5
#define __MODE_R32_REX      6
#define __MODE_R64          7
#define __MODE_R64_REX      8

typedef struct ia64_reg {
    char *r1;
    char *r2;
    char *r3;
    char *r4;
    char *r5;
    char *r6;
    char *r7;
    char *r8;
} ia64_reg;

const ia64_reg ia64_regtab[] = {
 { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" },
 { "al", "cl", "dl", "bl", "ah", "spl", "bpl", "dil" },
 { "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"},
 { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" },
 { "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" },
 { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" },
 { "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"},
 {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" },
 {"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }
};

#endif
