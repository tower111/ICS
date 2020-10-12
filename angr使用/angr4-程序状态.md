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
下一章展示仿真管理的全部内容，但是这里将会展示一个比较简单的接口演示符号执行的工作方式state.step()
