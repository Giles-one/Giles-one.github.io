---
title: 以glibc源码调试程序的方法
date: 2021-08-07 17:48:03
tags:
  - glibc源码
---
> 总结写在前,第一种方法最有效。第二种适合调试其他版本。第三种很磨练意志。
## 方法1

* 安装带调试的libc
  * `sudo apt install libc6-dbg`
  * `sudo apt install libc6-dbg:i386`
* 下载源码
  * 首先修改`/etc/apt/sources.list`，将`deb-src`配置开启
  * 更新`sudo apt update`
  * 使用`apt source`下载源码`apt source libc6-dev`
* 导入
  * `gdb file -d glibc/malloc/ -d glibc/libio/` 
  * `directory glibc/libio/`

## 方法2

### 查看glibc版本

```shell
giles@ubuntu:~/Desktop $ ldd /bin/bash
	linux-vdso.so.1 (0x00007fff9a575000)
	libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007f14d656d000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f14d6567000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f14d6375000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f14d66dc000)

giles@ubuntu:~/Desktop $ /lib/x86_64-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2) stable release version 2.31.
Copyright (C) 2020 Free Software Foundation, Inc.
...

giles@ubuntu:~/Desktop $ strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2) stable release version 2.31.

```
* `libc.so.6`链接的文件`/lib/x86_64-linux-gnu/libc.so.6`即是编译时默认链接的
* 通过执行或者strings 获取具体版本 `Ubuntu GLIBC 2.31-0ubuntu9.2`
### 下载glibc的源码  

> glibc的源码应该是在这里`https://launchpad.net/ubuntu/+source/glibc/`管理的 

访问[这里](https://launchpad.net/ubuntu/+source/glibc)`https://launchpad.net/ubuntu/+source/glibc`
![](https://files.catbox.moe/2zuo6a.png)
点开小三角 选择下载方式
```shell
giles@ubuntu:~/Desktop $ wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/glibc/2.31-0ubuntu9.2/glibc_2.31.orig.tar.xz
...
giles@ubuntu:~/Desktop $ xz -d glibc_2.31.orig.tar.xz 
giles@ubuntu:~/Desktop $ tar -xvf glibc_2.31.orig.tar 
...
```
如果上图并没有找到你所需的版本，在>[code页](https://code.launchpad.net/ubuntu/+source/glibc),在相应`*-devel` branch内找具体版本的`commit id`
git下来之后,`git checkout commit_id`

### 加载源码

1. `gdb file -d glibc/malloc/ -d glibc/libio/` 
2. `directory glibc/libio/`

两种都行,调试对应的模块使用对应的路径。
## 方法三 (编译)

[这个师傅](https://www.cnblogs.com/zq10/p/14314952.html)

说实话,我编译过,很耗时,编译后很大,也很容易出错。一定要注意出错的信息，需要改源码或者apt安装些什么。好运。

