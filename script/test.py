#!/usr/bin/env python

import sys
import subprocess
import unittest

class TestDisassembleRaw(unittest.TestCase):
    def create_bin(self, data):
        v=str()
        f=open("tmp.bin", 'wb')

        for i in data:
            v = v + i
            if len(v) == 2:
                h = int(str(v), base=16)
                f.write(chr(h).encode("ISO-8859-1"))
                v = str()
        f.close()

    # ADD - 0x00 - 0x05
    def test_add(self):
        self.create_bin("0011")
        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            "ADD\tDWORD [rcx], DL")
        disasm.stdout.close()

    #  OR - Logical inclusive OR 0x08-0d
    def test_or(self):
        self.create_bin("0811")
        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            "OR\tDWORD [rcx], DL")
        disasm.stdout.close()

    # ADC - Add with cary 0x10-0x15
    def test_adc(self):
        self.create_bin("15deadbeef")
        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            "ADC\teax, 0xefbeadde")
        disasm.stdout.close()

    # SBB - Subtraction with borrow 0x18-1d
    def test_sbb(self):
        self.create_bin("180119021a031b05555555551cff1d12341234")
        inst = "sbb\tDWORD [rcx], AL\n" + \
        "sbb\tDWORD [rdx], eax\n" + \
        "sbb\tAL, DWORD [rbx]\n"+ \
        "sbb\teax, DWORD [rip+0x55555555]\n" + \
        "sbb\tal, 0xff\n" + \
        "sbb\teax, 0x34123412"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # AND - Logical AND 0x20-0x25
    def test_and(self):
        self.create_bin("200621072208230924ff25ffffffff")
        inst = "and\tDWORD [rsi], AL\n" +\
            "and\tDWORD [rdi], eax\n" +\
            "and\tCL, DWORD [rax]\n" +\
            "and\tecx, DWORD [rcx]\n" +\
            "and\tal, 0xff\n" +\
            "and\teax, 0xffffffff"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # Subtraction 0x28-0x2d
    def test_sub(self):
        self.create_bin("281029112a122b132cff2dffffffff")
        inst = "sub\tDWORD [rax], DL\n" +\
            "sub\tDWORD [rcx], edx\n" +\
            "sub\tDL, DWORD [rdx]\n" +\
            "sub\tedx, DWORD [rbx]\n" +\
            "sub\tal, 0xff\n" +\
            "sub\teax, 0xffffffff"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # Logical exclusive OR 0x30-0x35
    def test_xor(self):
        self.create_bin("3015feffffff31163217331834ff35ffffffff")
        inst = "xor\tDWORD [rip+0xfffffffe], DL\n" +\
            "xor\tDWORD [rsi], edx\n" +\
            "xor\tDL, DWORD [rdi]\n" +\
            "xor\tebx, DWORD [rax]\n" +\
            "xor\tal, 0xff\n" +\
            "xor\teax, 0xffffffff"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # Compare two operands 0x38-0x3d
    def test_cmp(self):
        self.create_bin("3819391a3a1b3b1dffffffff3cff3dffffffff")
        inst = "cmp\tDWORD [rcx], BL\n" +\
            "cmp\tDWORD [rdx], ebx\n" +\
            "cmp\tBL, DWORD [rbx]\n" +\
            "cmp\tebx, DWORD [rip+0xffffffff]\n" +\
            "cmp\tal, 0xff\n" +\
            "cmp\teax, 0xffffffff"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # PUSH 0x50+r - PUSH 0x57
    def test_push(self):
        reg64 = [ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" ]
        opcode = 50
        for opcode in range (50, 57):
            self.create_bin(str(opcode))
            disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
            inst = "push\t"+reg64[opcode-50]
            self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
                inst)
            disasm.stdout.close()

    # POP 0x58 - 0x5f
    def test_pop(self):
        reg64 = [ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" ]
        opcode = 50
        for opcode in range (0x58, 0x5f):
            self.create_bin(hex(opcode).replace("0x",""))
            disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
            inst = "pop\t"+reg64[opcode-0x58]
            self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
                inst)
            disasm.stdout.close()

    # IMUL 0x69, 0x6b
    def test_imul(self):
        self.create_bin("691e123412346b1dffffffff11")
        inst = "imul\tebx, DWORD [rsi], dword 0x34123412\n" +\
            "imul\tebx, DWORD [rip+0xffffffff], byte 0x11"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # PUSH 0x6a byte
    def test_push_byte(self):
        self.create_bin("6a116a22")
        inst = "push\tbyte 0x11\n" +\
            "push\tbyte 0x22"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # INSB/D OUTSB/D
    def test_insb(self):
        self.create_bin("6c6d6e6f")
        inst = "insb\tbyte [rdi], dx\n" +\
            "insd\tdword [rdi], dx\n" +\
            "outsb\tdx, byte [rsi]\n" +\
            "outsd\tdx, dword [rsi]"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # Jumps
    def test_jumps(self):
        self.create_bin("70557155725573557455755576557755785579557a557b557c557d557fff")
        inst = \
        "JO\t0x57\n" +\
        "JNO\t0x59\n" +\
        "JB\t0x5b\n" +\
        "JNB\t0x5d\n" +\
        "JZ\t0x5f\n" +\
        "JNZ\t0x61\n" +\
        "JBE\t0x63\n" +\
        "JNBE\t0x65\n" +\
        "JS\t0x67\n" +\
        "JNS\t0x69\n" +\
        "JP\t0x6b\n" +\
        "JNP\t0x6d\n" +\
        "JL\t0x6f\n" +\
        "JNL\t0x71\n" +\
        "JNLE\t0x1d"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # 0x80
    def test_80h(self):
        self.create_bin("80050111111111800911801255801e22802755802a22803122803d3333333333")
        inst = \
            "add\tDWORD [rip+0x11111101], byte 0x11\n" +\
            "or\tDWORD [rcx], byte 0x11\n" +\
            "adc\tDWORD [rdx], byte 0x55\n" +\
            "sbb\tDWORD [rsi], byte 0x22\n" +\
            "and\tDWORD [rdi], byte 0x55\n" +\
            "sub\tDWORD [rdx], byte 0x22\n" +\
            "xor\tDWORD [rcx], byte 0x22\n" +\
            "cmp\tDWORD [rip+0x33333333], byte 0x33"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    def test_81h(self):
        self.create_bin("813fffffffff")
        inst = "cmp\tDWORD [rdi], dword 0xffffffff"
        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

if __name__ == "__main__":
    unittest.main()
