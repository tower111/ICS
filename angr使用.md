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