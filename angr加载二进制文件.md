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
cle加载器(cle.Loader)i表示整个已加载二进制对象的组合，它们被加载并映射到单个内存空间。该加载器可以处理其文件类型（cle.Backend）例如cle.ELF用于加载ELF文件。

在内存中也会有一些对象与加载的二进制文件不对应，如用于提供本地线程存储支持的对象，以及用于提供未解析富豪的externs对象

用loader.all_objects能加载完整的CLE项目，以及一些有针对性的分类

