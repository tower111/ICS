---
title: angr3-解析引擎
tags: angr,工具
renderNumberedHeading: true
grammar_cjkRuby: true
---

# 使用位向量

创建一个虚拟的对象和状态
```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```
位向量只是位序列，用有界整数的语义进行解释以进行算数运算

``` python
# 64-bit bitvectors with concrete values 1 and 100
>>> one = state.solver.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# create a 27-bit bitvector with concrete value 9
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```
位向量可以进行数学运算
