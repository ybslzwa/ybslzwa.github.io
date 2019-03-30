---
title: 恢复 linux 的 root 密码
categories:
  - Linux_OM
tags:
  - Null
---

这几天遇到一台靶机，这个 web 站点我一直没有办法拿下，没有办法，菜鸡的我只有想想办法白盒了，但是并没有这台 linux 的 root 密码，这就很难受了，就在网上查了点资料，在这里记录一下我常用的 linux 发行版恢复 root 密码的方法。  

# 0x1 centos 6.9

## 0x11 修改 kernel arguments

在 `centos 6.9` 这个版本中一开机会有5秒左右的倒计时，这里我们按下任意键，就会来到这个界面。

![CentOS_6.9_1](/image/2019-03-03-linux_changed_root_passwd/CentOS_6.9_1.png)

然后，按下 `a` 就会进入到

![CentOS_6.9_2](/image/2019-03-03-linux_changed_root_passwd/CentOS_6.9_2.png)

在最后加上

```
rw init=/bin/bash
rw 是挂载硬盘的时候具有读写权限
指定运行 /bin/bash 而不是 /sbin/init
```

按下 `Enter` ， 经过一系列刷屏（引导），就进入到

![CentOS_6.9_3](/image/2019-03-03-linux_changed_root_passwd/CentOS_6.9_3.png)



## 0x12 修改 root 密码

在这里我们就运行 `passwd` 常规改密码就好了

![CentOS_6.9_4](/image/2019-03-03-linux_changed_root_passwd/CentOS_6.9_4.png)

最后 `ctrl` + `alt` + `del` 重启系统。

到这里就完成了所有的操作了。



# 0x2 centos 7

## 0x21 修改 kernel arguments`

`centos 7` 和 `centos 6` 的步骤是差不多的，首先启动系统按下任意键就到了个页面，选择第二个并按下 `e`

![CentOS_7-2019-03-03-00-11-34](/image/2019-03-03-linux_changed_root_passwd/CentOS_7-2019-03-03-00-11-34.png)

进入到

![CentOS_7-2019-03-03-00-12-19](/image/2019-03-03-linux_changed_root_passwd/CentOS_7-2019-03-03-00-12-19.png)

在 linux16 这一行的最后，添加

```
rw init=/bin/bash
```

 并按下 `ctrl` + `x` 进行启动系统



## 0x22 修改 root 密码

这里和 `centos 6` 的操作基本一致，所以不再赘述了。



## 0x33 SElinux

在有一次我修改 `centos 7` 密码的时候，重启发现所有的账户都被禁止登陆了，这个时候我也意识到了，可能是这里修改密码，触发了某个内核中的安全模块，这个时候我们就需要想办法抢救一下这台机器了。

在百度上面找到了答案，是因为 `centos 7` 默认就开启 [`SElinux`](https://wiki.centos.org/zh/HowTos/SELinux) 的 `Enforcing` 模式，它会在系统上启用并实施 `SELinux` 的安全性政策，拒绝存取及记录行动。

这个时候我们只需要 `重新标签整个档案系统` ，具体操作如下：

```sh
touch /.autorelabel
reboot -f
```

在根目录创建这个文件，在开机的时候会卡住几分钟（重新标签整个档案系统），然后就可以使用刚才我们所设置的新密码登陆啦。

注：这里如果还是出现错误，重新完成上述步骤，就可以了。



# 0x3 ubuntu 14.04

## 0x31 修改 kernel arguments

在 `ubuntu 14.04` 中，开机的同时按下任意键，进入到这里，选择 `Advanced options for Ubuntu`

![ubuntu-14.04.5_1](/image/2019-03-03-linux_changed_root_passwd/ubuntu-14.04.5_1.png)

按下 `e` 键，进入到

![ubuntu-14.04.5_2](/image/2019-03-03-linux_changed_root_passwd/ubuntu-14.04.5_2.png)

在 `linux`  这一行的末尾加上

```
rw init=/bin/bash
```

![ubuntu-14.04.5_3](/image/2019-03-03-linux_changed_root_passwd/ubuntu-14.04.5_3.png)

这里和 `centos 7` 的操作相同，按下 `ctrl` + `x`

经过刷屏，则进入到

![ubuntu-14.04.5_4](/image/2019-03-03-linux_changed_root_passwd/ubuntu-14.04.5_4.png)



## 0x32 修改 root 密码

这里和 `centos 6` 的操作基本一致，所以不再赘述了。



# 0x4 Reference

- [https://en.wikipedia.org/wiki/Init](https://en.wikipedia.org/wiki/Init)
- [https://wiki.archlinux.org/index.php/kernel_parameters](https://wiki.archlinux.org/index.php/kernel_parameters)

- [https://www.kernel.org/doc/Documentation/admin-guide/kernel-parameters.txt](https://www.kernel.org/doc/Documentation/admin-guide/kernel-parameters.txt)


