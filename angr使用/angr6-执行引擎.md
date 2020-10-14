---
title: angr6-执行引擎
tags: 新建,模板,小书匠
renderNumberedHeading: true
grammar_cjkRuby: true
---

当要求在angr中执行某个步骤时，必须实际执行该步骤。angr使用一系列引擎来模拟给定代码段对输入状态的影响。
angr是按照顺序尝试所有可用引擎，采用一个能处理此步骤的引擎。
- 当上一步中带入一些无法继续的状态时 failure引擎将会启动。
- 上一步在系统调用中结束时syscall引擎将会启动
- 当勾住当前地址时hook引擎启动
- 启动UNICORN状态选项并且状态中没有符号数据时unicorn引擎将会启动。
- 进入最后callback的时候VEX引擎将会启动。

# SimSuccessors
实际尝试所有引擎的代码是`project.factory.successors(state, **kwargs)`，