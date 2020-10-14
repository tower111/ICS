---
title: angr5-仿真管理 
tags: 工具,angr
renderNumberedHeading: true
grammar_cjkRuby: true
---

SimulationManager允许同时控制状态组的符号执行，应用搜索策略探索整个状态空间。

state被组织为stashes（存储区）可以根据需要前进，过滤，合并，移动。（例如：这允许你能够以不同的速率步进两个不同的stashes，然后合并他们）。

大多数操作的默认stash是active stash（在初始化新的模拟状态管理器时，你的states将会防止的地方）。

# setpping
模拟管理器最基本的功能是向前移动一个基本块

``` python

>>> import angr
>>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simgr(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
>>> simgr.active
[<SimState @ 0x400540>]
```
当一个状态遇到符号分之条件时，两个继承状态都将显示在stash，并且可以使它们两个都同步。

如果不在乎控制分析，只想逐步执行直到没有任何可以执行的步骤可以使用.run()方法。

``` python
# Step until the first symbolic branch
>>> while len(simgr.active) == 1:
...    simgr.step()

>>> simgr
<SimulationManager with 2 active>
>>> simgr.active
[<SimState @ 0x400692>, <SimState @ 0x400699>]

# Step until everything terminates
>>> simgr.run()
>>> simgr
<SimulationManager with 3 deadended>
```
当状态在执行期间无法产生任何后缀时（例如：因为到达exit系统调用，将其从活动stash中删除）将会被放置在`deadended`(无用)stash。

# stash管理
看看其他的stash怎样工作的。

从stashes之间移动状态使用.move()。下面的例子展示移动其中输出中具有特定字符串的内容。（stash的种类下文将会讲到）

``` python
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```
创建一个新的stash,名字叫做"authenticated"。


每个stash是一个列表，可以用索引或者遍历该列表以访问每个单独的状态，也提供了一些替代的方法可以访问这些状态。如果在stash名字前面添加`one_`将访问第一个stash。如果在stash名字前面添加`mp_`将会得到stash的多重版本（多重版本的含义可以看下面的例子，最后输出的应该是导致正确和错误的输入）

``` python
>>> for s in simgr.deadended + simgr.authenticated:
...     print(hex(s.addr))
0x1000030
0x1000078
0x1000078

>>> simgr.one_deadended
<SimState @ 0x1000030>
>>> simgr.mp_authenticated
MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
>>> simgr.mp_authenticated.posix.dumps(0)
MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])
```

# stash类型

angr提供了一些默认的分类

- 除非指定了备用stash，否则默认情况下将逐步执行状态。
- deadended  当state由于某种原因无法继续执行时，state将进入死锁状态，包括不再有有效的指令，所有后继者的状态都到了不满意的状态（应该是探索的时候指定的avoid），或者无效的指令指针。
- unconstrained 如果save_unconstrained选项给提供给SimulationManager 构造函数。确定为不受约束的状态（由用户数据或其他符号源数据控制的指令指针）会放到这里。
- unsat 如果把save_unsat选项传递给SimulationManager 构造函数，确定为无法满足的state(它们具有矛盾的约束)将会放到这里。

**还有一个states的列表但是不是stash：`errored`如果执行过程中引发错误，则将状态包装在ErrorRecord对象中该对象包含状态和引发的错误，然后将记录插入错误中。可以获取导致record.state错误的执行开始时的状态，可以看到record.state引发的错误还可以使用record.debug()在错误的地方启动调试shell。**

# 简单探索
常见操作是找到到达某个地址的状态，同时丢弃通过另一个地址的所有状态。模拟管理提供了一个.explore()方法。

结束的可以是一个地址或者一个地址列表或者是一个到达某种准则的函数。