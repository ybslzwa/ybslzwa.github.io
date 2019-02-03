---
title: 怎么使用 woboq_codebrowser 生成代码浏览器
categories:
  - Daily
tags:
  - Null
---

记一次生成代码浏览器的过程，这几天看 glibc 内存分配这块的代码，调试`house of orange`这个漏洞的时候，malloc 的报错信息一个跟我在源码当中看到的信息不一致。

所以，我决定去寻找“真理”，我发现我的系统`ubuntu 16.04 x64`的 glibc 版本号为 2.23，而我在看的源码版本为2.28，由于两个版本不一致导致了这样尴尬的事情发生，由于在线代码阅读器只有 2.28 版本的 glibc，所以我决定自己编译一个 2.23 版本的。



# 0x1 安装生成器

由于我之前一直在 [**woboq**](https://code.woboq.org/userspace/glibc/) 上面看 glibc 的源码，觉得这个比较好用，所以这次就直接用它生成代码浏览器了。

## 1. 选择安装方式

由于我怕直接编译生成器会遇见莫名其妙的问题（主要是懒），所以我决定使用 apt 添加源的方式安装。

其他的安装方式在 [**这里**](https://woboq.com/codebrowser-download.htmlr)

## 2. 安装

由于我是`ubuntu 16.04`所以添加下面这条源进行安装，如果是 ubuntu 其他版本在 [**这里**](https://software.opensuse.org/download/package?project=home:pansenmann:woboq&package=woboq-codebrowser) 找到相对应的源。

```
sudo sh -c "echo 'deb http://download.opensuse.org/repositories/home:/pansenmann:/woboq/xUbuntu_16.04/ /' > /etc/apt/sources.list.d/home:pansenmann:woboq.list"
sudo apt-get update
sudo apt-get install woboq-codebrowser
```



# 0x2 运行生成器

我在 [**这里**](https://github.com/woboq/woboq_codebrowser) 找到了如何使用生成器，首先我们需要 [**bear**](https://github.com/rizsotto/Bear) 配合 make 编译 glibc-2.23 的源码，用于生成 [**编译数据库**](https://sarcasm.github.io/notes/dev/compilation-database.html#what-is-a-compilation-database)，再用 `compile_commands.json` 配合生成器生成代码浏览器。

## 1. 编译 glibc-2.23

### 下载源码

从 [**这里**](http://ftp.gnu.org/gnu/libc/glibc-2.23.tar.gz) 下载源码，然后我们需要将源码解压到当前目录中。

```
root@xxx:~# tar -zxvf glibc-2.23.tar.gz
```

### 编译源码

由于在 glibc-2.23 源码目录下 `./configure` 会报错 `configure: error: you must configure in a separate build directory`， 所以我们在 glibc-2.23 的同级目录下创建一个文件夹。

```
root@xxx:~# mkdir glibc-build
```

进入 glibc-build 配置configure

```
root@xxx:~/glibc-build# ../glibc-2.23/configure --prefix=~/glibc-build
```

接下来我们开始编译

```
root@xxx:~/glibc-build# bear make -j9
```

## 2. 生成代码浏览器

当编译完成过后，会在 glibc-build 下生成 `compile_commands.json` 将它移入glibc-2.23 源码目录下。

```
root@xxx:~/glibc-build# mv compile_commands.json ../glibc-2.23/
```

创建一个文件夹，一会生成器会将生成的所有文件放进去

```
root@xxx:~# mkdir version-2.23
```

运行代码浏览器

```
root@xxx:~/glibc-2.23# codebrowser_generator -b . -a -o ~/version-2.23 -p glibc-2.23:.:beta
root@xxx:~/glibc-2.23# codebrowser_indexgenerator ~/version-2.23
```

到这里代码浏览器就生成完毕了，但是现在遇到一个问题，就是由于我们是通过apt进行安装的，所以我并没有找到 `data` 这个文件夹，运行起来和 [**示例**](https://code.woboq.org/userspace/glibc/) 有很大的区别。

没办法去找找线索把，在他们项目的 [**github**](https://github.com/woboq/woboq_codebrowser) 找到了 data 这个文件夹。

```
root@xxx:~# git clone https://github.com/woboq/woboq_codebrowser
root@xxx:~# cp ./woboq_codebrowser/data . -r
```

现在这个项目的结构如下：

```
.
├── data
│   └── jquery
└── version-2.23
    ├── fnSearch
    ├── glibc-2.23
    ├── include
    └── refs

```

到现在为止，和 [**示例**](https://code.woboq.org/userspace/glibc/) 差一个搜索功能，在项目的 [**github**](https://github.com/woboq/woboq_codebrowser) 上面找到了。

```
默认情况下，file:// 出于安全原因，浏览器不允许启用AJAX 
```

我用的火狐浏览器，在 `about:config` 将 `security.fileuri.strict_origin_policy` 设置为 false，但是还是没有办法搜索，这就很难受了。没办法咯，搭建个web服务器把。

## 3. 搭建 web 服务器 

直接使用 apt 搭建 apache 服务器

```
apt-get install apache2
service apache2 start
```

将代码浏览器的文件全部放入 web 的目录

```
root@xxx:~# mv data /var/www/html/
root@xxx:~# mv version-2.23 /var/www/html/
```

这里我用 html 写了一个简单的导航，将下列代码放入`/var/www/html/index.html`，就完成了。

```html
<!DOCTYPE html>

<html>
<head>
<meta charset="utf-8">
<title>Welcome</title>
</head>

<body>
<center>
<h1>目录</h1>
<a href="./version-2.23/glibc-2.23/index.html">glibc-2.23</a>

</center>
</body>
</html>
```

## 4. 代码浏览器效果图

![index](/image/2019-02-04-how-to-use-woboq-codebrowser/index.png)

![search](/image/2019-02-04-how-to-use-woboq-codebrowser/search.png)

![version](/image/2019-02-04-how-to-use-woboq-codebrowser/version.png)

# 0x3 Reference

[https://code.woboq.org/](https://code.woboq.org/)

[https://github.com/woboq/woboq_codebrowser](https://github.com/woboq/woboq_codebrowser)

[http://www.sysnote.org/2015/08/25/use-new-glibc/](http://www.sysnote.org/2015/08/25/use-new-glibc/)