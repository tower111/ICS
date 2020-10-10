---
title: angr使用
tags: 工具,angr
renderNumberedHeading: true
grammar_cjkRuby: true
---

# 介绍
原始文档来自[https://docs.angr.io/core-concepts/toplevel](https://docs.angr.io/core-concepts/toplevel) 这里更多是整理，方便查找

# 基本特性

archinfo.arch提供了有关其运行cpu的很多信息相关介绍[https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py)
``` python
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true
```