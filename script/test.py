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
            "add\tdword [rcx], dl")
        disasm.stdout.close()

    #  OR - Logical inclusive OR 0x08-0d
    def test_or(self):
        self.create_bin("0811")
        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            "or\tdword [rcx], dl")
        disasm.stdout.close()

    # ADC - Add with cary 0x10-0x15
    def test_adc(self):
        self.create_bin("15deadbeef")
        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            "adc\teax, dword 0xefbeadde")
        disasm.stdout.close()

    # SBB - Subtraction with borrow 0x18-1d
    def test_sbb(self):
        self.create_bin("180119021a031b05555555551cff1d12341234")
        inst = "sbb\tdword [rcx], al\n" + \
        "sbb\tdword [rdx], eax\n" + \
        "sbb\tal, dword [rbx]\n"+ \
        "sbb\teax, dword [rip+0x55555555]\n" + \
        "sbb\tal, byte 0xff\n" + \
        "sbb\teax, dword 0x34123412"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # AND - Logical AND 0x20-0x25
    def test_and(self):
        self.create_bin("200621072208230924ff25ffffffff")
        inst = "and\tdword [rsi], al\n" +\
            "and\tdword [rdi], eax\n" +\
            "and\tcl, dword [rax]\n" +\
            "and\tecx, dword [rcx]\n" +\
            "and\tal, byte 0xff\n" +\
            "and\teax, dword 0xffffffff"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # Subtraction 0x28-0x2d
    def test_sub(self):
        self.create_bin("281029112a122b132cff2dffffffff")
        inst = "sub\tdword [rax], dl\n" +\
            "sub\tdword [rcx], edx\n" +\
            "sub\tdl, dword [rdx]\n" +\
            "sub\tedx, dword [rbx]\n" +\
            "sub\tal, byte 0xff\n" +\
            "sub\teax, dword 0xffffffff"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # Logical exclusive OR 0x30-0x35
    def test_xor(self):
        self.create_bin("3015feffffff31163217331834ff35ffffffff")
        inst = "xor\tdword [rip+0xfffffffe], dl\n" +\
            "xor\tdword [rsi], edx\n" +\
            "xor\tdl, dword [rdi]\n" +\
            "xor\tebx, dword [rax]\n" +\
            "xor\tal, byte 0xff\n" +\
            "xor\teax, dword 0xffffffff"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # Compare two operands 0x38-0x3d
    def test_cmp(self):
        self.create_bin("3819391a3a1b3b1dffffffff3cff3dffffffff")
        inst = "cmp\tdword [rcx], bl\n" +\
            "cmp\tdword [rdx], ebx\n" +\
            "cmp\tbl, dword [rbx]\n" +\
            "cmp\tebx, dword [rip+0xffffffff]\n" +\
            "cmp\tal, byte 0xff\n" +\
            "cmp\teax, dword 0xffffffff"

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
        inst = "imul\tebx, dword [rsi], dword 0x34123412\n" +\
            "imul\tebx, dword [rip+0xffffffff], byte 0x11"

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
        "jo\t0x57\n" +\
        "jno\t0x59\n" +\
        "jb\t0x5b\n" +\
        "jnb\t0x5d\n" +\
        "jz\t0x5f\n" +\
        "jnz\t0x61\n" +\
        "jbe\t0x63\n" +\
        "jnbe\t0x65\n" +\
        "js\t0x67\n" +\
        "jns\t0x69\n" +\
        "jp\t0x6b\n" +\
        "jnp\t0x6d\n" +\
        "jl\t0x6f\n" +\
        "jnl\t0x71\n" +\
        "jnle\t0x1d"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    # 0x80
    def test_80h(self):
        self.create_bin("80050111111111800911801255801e22802755802a22803122803d3333333333")
        inst = \
            "add\tdword [rip+0x11111101], byte 0x11\n" +\
            "or\tdword [rcx], byte 0x11\n" +\
            "adc\tdword [rdx], byte 0x55\n" +\
            "sbb\tdword [rsi], byte 0x22\n" +\
            "and\tdword [rdi], byte 0x55\n" +\
            "sub\tdword [rdx], byte 0x22\n" +\
            "xor\tdword [rcx], byte 0x22\n" +\
            "cmp\tdword [rip+0x33333333], byte 0x33"

        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

    def test_81h(self):
        self.create_bin("813fffffffff")
        inst = "cmp\tdword [rdi], dword 0xffffffff"
        disasm = subprocess.Popen(["./rdisasm","-braw", "tmp.bin"], stdout=subprocess.PIPE)
        self.assertEqual(str(disasm.stdout.read(), encoding="utf-8").rstrip(),
            inst)
        disasm.stdout.close()

if __name__ == "__main__":
    unittest.main()
