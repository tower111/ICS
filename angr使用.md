---
title: angr使用
tags: 工具,angr
renderNumberedHeading: true
grammar_cjkRuby: true
---

# 介绍
原始文档来自[https://docs.angr.io/core-concepts/toplevel](https://docs.angr.io/core-concepts/toplevel) 这里更多是整理，方便查找

# 基本特性

archinfo.arch提供了有关其运行cpu的很多信息相关代码在[https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py)
``` python
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true
```
# 加载
把二进制文件加载到虚拟地址空间中，处理模块叫CLE，里面的\.loader属性提供了各种加载的信息，包括**内存的加载地址，各个地址的权限和保护信息，库文件的信息以及加载地址信息**

在[https://docs.angr.io/core-concepts/loading](https://docs.angr.io/core-concepts/loading)查看更多
``` python
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # may look a little different for you!
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object  # we've loaded several binaries into this project. Here's the main one!
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack  # sample query: does this binary have an executable stack?
False
>>> proj.loader.main_object.pic  # sample query: is this binary position-independent?
True
```
# 工厂 factory
factory 提供了经常使用的功能project.factory