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