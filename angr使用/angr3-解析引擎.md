---
title: angr3-解析引擎
tags: angr,工具
renderNumberedHeading: true
grammar_cjkRuby: true
---

# 使用位向量

创建一个虚拟的对象和状态
```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```
位向量只是位序列，用有界整数的语义进行解释以进行算数运算

``` python
# 64-bit bitvectors with concrete values 1 and 100
>>> one = state.solver.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# create a 27-bit bitvector with concrete value 9
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```
位向量可以进行数学运算

``` python
>>> one + one_hundred
<BV64 0x65>

# You can provide normal python integers and they will be coerced to the appropriate type:
>>> one_hundred + 0x100
<BV64 0x164>

# The semantics of normal wrapping arithmetic apply
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```
不同长度位向量扩展为相同之后才能运算

``` python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```
引入符号

``` python
# Create a bitvector symbol named "x" of length 64 bits
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```
 可以对它们执行任意数量的算术运算，但是不会得到数字而是得到AST（抽象语法树，可以转化为SMT求解器如z3的约束）
 
 

```python

>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```
如何处理AST

每个AST都包含.op和.args

``` python
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__floordiv__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)
```
我们将使用“位向量”一词来指代其最高操作产生位向量的任何AST
# 符号约束

任何两个相似的AST之间执行比较操作将产生一个bool值
```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```

不要在if或while语句的调价下直接使用便来给你之间的比较，因为答案可能没有具体的真实值。即使有一个具体真实值如果>>100也会引发异常。可以使用solver.is_true和solver.is_false来判断真假性  0
``` python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes) 
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```
# 约束求解
可以对符号值加以限制。x和y的值每次运行都可能不同，但是要满足add里面的几个要求

``` python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4
```
从这里课以看出来如何设置输入使这个输入能满足要求
``` python
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```
如果添加冲突或自相矛盾的约束针对它的查询讲会引发一场，可以用下面的命令查看可满足性。

``` python
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False
```

能评估更多变量而不止一个

``` python
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```
eval可以将任何位向量转化为python原语同时保证状态的完整性。

变量x和y虽然是在之前的状态创建但是现在的状态依然可以使用，可以看出变量没有任何一种状态，可以自由存在

# 浮点数
浮点数不是宽度二十排序，可以用FPV和FPS创建

``` python
# fresh state
>>> state = proj.factory.entry_state()
>>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
```
angr提供了舍入的方式，显式调用fp操作函数(如solver.fpAdd),并将舍入模式（solver.fp.RE\_\*）中的一个作为参数。

约束和求解与之前方式相似
``` python
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```
浮点数和位向量之间可以转换

``` python
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

>>> state.solver.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> state.solver.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>
```
这些转化将保留位模式，就像浮点指针强制转化为int指针一样。

当然angr也提供了数值间的转化，可以把浮点数强制转化为int(需要舍入)

``` python
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>
```
上面的例子中也可以使用带符号的参数

# 更多解析方法
eval提供了一个表达式的可能解决方案，但是如果想要多个表达式该怎么办（多个方程组），如果需要确保解决方案唯一该怎么办，求解器提供了几种常见的求解模式的方法。

expression 表达式
- solver.eval(expression) 给定表达式的一种可能的方案。
-  solver.eval_one(expression) 给出表达式的一种解决方案，如果不止一种则报错
-  solver.eval_upto(expression, n) 将提供n个表达式的解决方案，不够n个有多少返回多少。
-  solver.eval_atleast(expression, n) 将提供n个表达式的解决方案，不够n个将抛出错误。
-  solver.min(expression)，solver.max(expression)给定表达式的最小和最大解决方案

这些方法都可以使用下面的关键字

- extra_constraints 可以作为一个约束的元组传递