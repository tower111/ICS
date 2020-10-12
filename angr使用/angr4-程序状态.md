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

为什么时一个列表而不是只有一个successor state呢？ angr的符号执行过程只会针对被编译程序的单个指令，执行它们时SimState变异。如果遇到分支（如 if (x > 4)）在angr中将会返回一个结果

