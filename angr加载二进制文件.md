---
title: angr-2加载二进制文件
tags: 新建,模板,小书匠
renderNumberedHeading: true
grammar_cjkRuby: true
---

## 加载器

加载一个程序更深入的查看
``` python
>>> import angr, monkeyhex
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>
```