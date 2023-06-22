"""
 * @file pad_binary.py
 * @brief A tool to pad TDX module remaining bytes till page boundary with HLT opcodes.
"""

import sys
import os

PAGE_SIZE = 0x1000
HLT_OPCODE = 0xF4

def main():
  binary = sys.argv[1]
  statinfo = os.stat(binary)
  padding = PAGE_SIZE - (statinfo.st_size % PAGE_SIZE)
  f = open(binary,"ab")
  for i in range(padding):
    f.write(bytes([HLT_OPCODE]))
  f.close()

if __name__=='__main__':
    main()

