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
