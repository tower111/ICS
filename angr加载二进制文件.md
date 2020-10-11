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

``` python
# All loaded objects
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
 <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
 <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]

# This is the "main" object, the one that you directly specified when loading the project 。main是指定要加载的文件
>>> proj.loader.main_object
<ELF Object fauxware, maps [0x400000:0x60105f]>

# This is a dictionary mapping from shared object name to object  共享库有的名字和加载地址
>>> proj.loader.shared_objects
{ 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
  'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
  'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }

# Here's all the objects that were loaded from ELF files
# If this were a windows program we'd use all_pe_objects!
>>> proj.loader.all_elf_objects  #加载的所有elf文件，如果是windows把elf换成PE
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]

# Here's the "externs object", which we use to provide addresses for unresolved imports and angr internals
>>> proj.loader.extern_object #externs object 对未解析的导入和angr自身提供的地址
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>

# This object is used to provide addresses for emulated syscalls
>>> proj.loader.kernel_object  # 为模拟系统调用提供的地址
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>

# Finally, you can to get a reference to an object given an address in it
>>> proj.loader.find_object_containing(0x400000)
<ELF Object fauxware, maps [0x400000:0x60105f]>
```