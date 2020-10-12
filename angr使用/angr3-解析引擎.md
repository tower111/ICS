---
title: angr3-解析引擎
tags: angr,工具
renderNumberedHeading: true
grammar_cjkRuby: true
---

# 使用位向量

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```
