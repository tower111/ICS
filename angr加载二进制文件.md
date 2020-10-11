---
title: angr-2加载二进制文件
tags: 新建,模板,小书匠
renderNumberedHeading: true
grammar_cjkRuby: true
---

## 加载器

angr的加载模块叫CLE。

加载一个程序更深入的查看加载交互
``` python
>>> import angr, monkeyhex
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>
```
cle加载器(cle.Loader)i表示整个已加载二进制对象的组合，它们被加载并映射到单个内存空间。该加载器可以处理其文件类型（cle.Backend）