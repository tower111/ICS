---
title: angr顶级接口
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
还可以把块代码转化为其他表示形式(另一种类)，待补充：capstone结构和VEX IRSB结构

``` python
>>> block.capstone                       # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (that's a python internal address, not a program address)
<pyvex.block.IRSB at 0x7706330>
```
## states
代表程序的初始化镜像，获取到的是特定对象的工作模拟程序状态的一个。下面获取一个状态

``` python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```
SimState包含程序的内存，寄存器，文件系统信息，可以通过执行更改的实时数据，下面说明获取寄存器，内存

``` python
>>> state.regs.rip        # get the current instruction pointer
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # interpret the memory at the entry point as a C int
<BV32 0x8949ed31>
```
获取到的是位向量，不是python的int是另一种数据类型，每个位向量都有一个.length属性。下面是python的int和bitvector的转化

``` python
>>> bv = state.solver.BVV(0x1234, 32)       # create a 32-bit-wide bitvector with value 0x1234
<BV32 0x1234>                               # BVV stands for bitvector value
>>> state.solver.eval(bv)                # convert to python int
0x1234
```

可以用下面的方式把数据放到内存或者寄存器
``` python
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```
- 上面代码中的long可以换成更多表达`<type> (common values: char, short, int, long, size_t, uint8_t, uint16_t...)`
- mem可以存储位向量和python的int
- 使用.resolve可以得到位向量，.concrete可以得到python int
 
 
还有一些未初始化的值，64位位向量但是不包含数值，又叫符号变量
``` python
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>
```
## Simulation Managers 仿真管理器

对先前创建的状态进行操作，创建仿真管理器，也可以使用state列表

``` python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```
仿真管理器可以包含几种状态，除了上面的默认状态还可以用simer.active[0]进一步查看状态

接下来运行一个块

``` python
>>> simgr.step()
```
查看状态可以看到active已经被更新但是原始的state保持不变。

``` python
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # new and exciting!
<BV64 0x1020300>
>>> state.regs.rip                           # still the same!
<BV64 0x401670>
```
# 分析
angr提供一些内置的分析提供一些信息

``` python
>>> proj.analyses.            # Press TAB here in ipython to get an autocomplete-listing of everything:
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
 proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
 proj.analyses.CFGFast              proj.analyses.Reassembler
```
详细说明见[http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis](http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis)
下面生成cfg图，这是一个networkx的图（具体使用说明见python的networks库）

从一个地址生成cfg图，也可以从一个project获取cfg图

``` python
# Originally, when we loaded this binary it also loaded all its dependencies into the same virtual address  space
# This is undesirable for most analysis.
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph is a networkx DiGraph full of CFGNode instances
# You should go look up the networkx APIs to learn how to use this!
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# To get the CFGNode for a given address, use cfg.get_any_node
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```