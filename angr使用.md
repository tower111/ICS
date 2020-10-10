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
factory提供了一些方便的构造函数。常用的操作project.factory

## block
用 proj.factory.block()从一个地址上提取基本代码块，angr以代码块为单位分析代码。将会返回一个block对象，该对象包含很多信息

示例中给出了得出一个基本块的反汇编，指令条数，每条指令的地址。
``` python
>>> block = proj.factory.block(proj.entry) # lift a block of code from the program's entry point
<Block for 0x401670, 42 bytes>

>>> block.pp()                          # pretty-print a disassembly to stdout
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions                  # how many instructions are there?
0xb
>>> block.instruction_addrs             # what are the addresses of the instructions?
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```
还可以把块代码转化为其他表示形式(另一种类)

``` python
>>> block.capstone                       # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (that's a python internal address, not a program address)
<pyvex.block.IRSB at 0x7706330>
```

