---
title: angr5-仿真管理 
tags: 工具,angr
renderNumberedHeading: true
grammar_cjkRuby: true
---

SimulationManager允许同时控制状态组的符号执行，应用搜索策略探索整个状态空间。

state被组织为stashes（存储区）可以根据需要前进，过滤，合并，移动。（例如：这允许你能够以不同的速率步进两个不同的stashes，然后合并他们）。

大多数操作的默认stash是active stash（在初始化新的模拟状态管理器时，你的states将会防止的地方）
