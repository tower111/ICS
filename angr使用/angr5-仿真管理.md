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