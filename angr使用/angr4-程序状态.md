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

模拟的程序从标准输入获取数据，默认情况下angr将其视为无限的符号数据流。 