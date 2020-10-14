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

结束的可以是一个地址或者一个地址列表或者是一个到达某种准则的函数。当stashs中任意state与查找条件相匹配时，他们将会被放到`found` stash中并且终止执行（也就是只会有一个state满足）。然后你能查看found state或决定放弃它继续其他状态。

avoid格式和find一样，会把运行到的state放到avoided stash中然后继续执行。

num_find 参数可以控制多少个state会被放到find stash中，默认值为1。

例子查看[https://docs.angr.io/examples#reverseme-modern-binary-exploitation---csci-4968](https://docs.angr.io/examples#reverseme-modern-binary-exploitation---csci-4968)


``` python
>>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')


>>> simgr = proj.factory.simgr()


>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>


>>> s = simgr.found[0]
>>> print(s.posix.dumps(1))
Enter password: Congrats!

>>> flag = s.posix.dumps(0)
>>> print(flag)
g00dJ0B!

```
# 探索技术
angr附带了几项固定功能，可以让你自定义模拟管理器的行为。成为探索技术。
典型的例子是修改探索程序空间的模式默认的是"立即执行所有操作"实际上是广度优先搜索。

angr提供了改变它步进过程中的行为的接口，下一章会介绍编写自己的探测技术。

可以使用simgr.use_technique(tech)，其中tech是Exploration Technique子类的实例可以在angr.exoloration_techniques下找到angr的内置探测技术。

这是一些内置的探测技术
- DFS 深度优先搜索，一次仅使一个state保持活动，将其余放到deferred stash中知道其陷入deadends（死胡同）或出错
- Explorer 实现了 .explore()函数
- LengthLimiter 对状态通过的路径的最大长度设置上限。
- LoopSeer  使用合理的循环计数近似值来丢弃似乎经历多次循环的状态，把它们放到`spinning(旋转)`stash中如果我们用尽了其他可行的状态再将它们拉出。
- ManualMergepoint（手动合并点） 在程序中标记一个地址作为合并点，因此到达该地址的状态将会被短暂保留，并且在超时时间内达到同一点的任何其他状态将会被合并在一起。
- MemoryWatcher（内存观察者）见识simgr步骤之间系统上空闲/可用的内存量，并在内存太低时停止探索
- Oppologist（operation apologist 操作辩护者）开启之后遇到不受支持的指令也会用unicorn引擎模拟单个指令继续执行。
- Spiller  有太多状态处于活动状态时，可以将其中一些状态转储到磁盘上，保持比较低的内存小号。
- Threading  在步进过程中增加线程级别的并行性。python全局解释器的锁定，这里并没有多大用处。但是如果程序的分花费大量时间在angr的本机代码依赖项上将会有所收获。
- Tracer  （个人理解）使执行能够动态追踪动态库。动态追踪存储库有一些工具来生成这些轨迹。[https://github.com/angr/tracer](https://github.com/angr/tracer)
- Veritesting  自动识别有用合并点的MCU论文的实现 论文地址[https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf](https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf)
- 