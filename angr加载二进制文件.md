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
>>> proj.loader.find_object_containing(0x400000) #可以获得其中对给定地址对象的引用（给一个地址找到所在的对象）
<ELF Object fauxware, maps [0x400000:0x60105f]>
```
可以直接交互从它们提取元数据（刚被加载的时候的数据）

``` python
>>> obj = proj.loader.main_object

# The entry point of the object
>>> obj.entry  #对象的入口点（）
0x400580

>>> obj.min_addr, obj.max_addr  #最小和最大地址
(0x400000, 0x60105f)

# Retrieve this ELF's segments and sections
>>> obj.segments  #检索此ELF的段和节（内存大小，文件大小，虚拟地址，标志，偏移）
<Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
           <ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc

#通过地址查看段和节
# You can get an individual segment or section by an address it contains:
>>> obj.find_segment_containing(obj.entry)
<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# Get the address of the PLT stub for a symbol
>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'

# Show the prelinked base of the object and the location it was actually mapped into memory by CLE
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

