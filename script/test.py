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

if __name__ == "__main__":
    unittest.main()
