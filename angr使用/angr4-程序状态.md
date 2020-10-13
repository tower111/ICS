---
title: angr4-程序状态
tags: angr,工具
renderNumberedHeading: true
grammar_cjkRuby: true
---

这里讲会讲述state对象的结构以及如何以多种有用的方式与之交互。

# 复习：读写内存和寄存器
state.regs可以访问寄存器
state.mem可以读写访问内存

``` python
>>> import angr, claripy
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# copy rsp to rbp
>>> state.regs.rbp = state.regs.rsp

# store rdx to memory at 0x1000
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# dereference rbp
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved
```
# 基本执行
下一章展示仿真管理的全部内容，但是这里将会展示一个比较简单的接口演示符号执行的工作方式state.step()。这种方法将会展示一个符号执行的一个步骤，并返回一个名为SimSuccessors的对象，符号执行可以产生多个后继状态，这些状态能用多种方式进行分类。

successor 后继

现在我们关心的时此对象的.successors属性该属性是一个列表，包含给定步骤的所有常规后继对象。

为什么时一个列表而不是只有一个successor state呢？ angr的符号执行过程只会针对被编译程序的单个指令，执行它们时SimState变异。如果遇到分支（如 if (x > 4)）在angr中将会返回一个结果`<Bool x_32_1 > 4>`。

但是实际上采用真的分支还是假的分支呢，angr采用的时两者都用，在两个分支处分别添加约束为`x>4 和 !(x > 4)`

``` python
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state(stdin=angr.SimFile)  # ignore that argument for now - we're disabling a more complicated default setup for the sake of education
>>> while True:# 一步一步运行直到遇到一个分支产生两种successor状态
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699
```
**strcmp**是一个用符号模拟非常棘手的函数，其结果非常复杂。

模拟的程序从标准输入获取数据，默认情况下angr将其视为无限的符号数据流。 要执行约束求解并获得满足约束条件的可能的输入我们需要获得stdin实际内容的引用。
state.posix.stdin.load(0, state.posix.stdin.size)可以检索一个表示到目前位置从stdin读取的所有内容的位向量。（一般用于输出结果）

``` python
>>> input_data = state1.posix.stdin.load(0, state.posix.stdin.size)

>>> state1.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

>>> state2.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'
```

# 预设状态

上面的操作创建状态的方式只有一种 project.factory.entry_state(),实际上还有几种其他的方式
- .blank_state() 创建一个空白状态，其中大部分数据未初始化，当访问一个未初始化的数据时将返回一个不受约束的符号值。
- .entry_state()创建一个状态准备在主二进制文件入口点执行。
- .full_init_state()  创建一个这样的状态，该状态暂停在准备运行初始化器初始化所有东西，初始化器在主二进制文件的载入点运行之前，当运行完将跳转到载入点（还没有执行初始化器）
- .call_state() 构建一个准备好执行给定函数的状态

能通过构造函数的几个参数自定义状态

- 所有这些构造函数都可以使用参数`addr`来指定要启动的确切地址
- 可以用args传递命令行参数列表，并通过env传递环境变量字典到entry_state和full_init_state。 这些结构中的值可以是字符串或者位向量，并将被序列化为state作为模拟执行的参数和环境。默认args是个空列表。
- 如果希望argc设为符号可以将符号位向量作为argc传递给entry_state和full_state构造函数。注意：如果这样需要向结果state添加一个约束即argc的值不能大于传递给args的数量。
- 调用状态：`.call_state(addr, arg1, arg2, ...)` addr是要调用的函数的地址，argN是该函数的第N个参数，可以是python整数，字符串或数组或位向量。如果想要分配实际内存并将指针传递给对象则应将其包装在PointerWrapper中（例如：angr.PointerWrapper("point to me!")），这个API的结果可能有点不可预测......（是不能使用吗，angr团队正在优化）
- 为了指定一个call_state函数的调用约定，可以用SimCC接口作为cc参数。SimCC接口查看[http://angr.io/api-doc/angr.html#module-angr.calling_conventions](http://angr.io/api-doc/angr.html#module-angr.calling_conventions)

所有参的解析 http://angr.io/api-doc/angr.html#angr.factory.AngrObjectFactory

# 低级内存接口

state.mem 接口从内存中加载或存储某种类型的数据时很方便，但是对内存范围进行原始数据的加载和存储时非常麻烦。

可以表示一个平面地址空间：state.memory。 一般使用.load(addr,size)和.store(addr,val)方法进行存取

``` python
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
```
state.memory没有对大小端的设置，数据都是以打断存储方式存储和加载的。

可以使用endness指定是否要对字节进行交换（可以实现大小端转化）

endness时archinfo软件包中Endness美剧的成员之一，该包保存有关angr的CPU体系结构的声明性数据。

``` python
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67453201>
```

# state选项
添加一些state的选项，这些选项有时候会优化行为，而在其他情况下不利，可以用state.options进行更改.

``` python
# Example: enable lazy solves, an option that causes state satisfiability to be checked as infrequently as possible.#
# This change to the settings will be propagated to all successor states created from this state after this line. #对设置的更改将传播到由此状态创建的所有后继状态
>>> s.options.add(angr.options.LAZY_SOLVES)

# Create a new state with lazy solves enabled
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})

# Create a new state without simplification options enabled
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)
```
# 状态插件