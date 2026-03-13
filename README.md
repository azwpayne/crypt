# crypt

crypt is a pure Python implementation of common cryptographic algorithms
such as AES, RSA, SHA, etc.

For now, I am only concerned with implementation and Enhanced Transformation, rather
than the principles of algorithms

## Todo

- [ ] docs
- [ ] code quality
    - code style
    - linting
    - tests
    - etc
- [ ] more algorithms

# premise

8 bit = 1 byte(B)
bytes 是二进制数据的"只读视图"，bytearray 是"可编辑视图"。 处理网络协议、文件 I/O 时，

- 接收用 bytearray（可修改），
- 发送用 bytes（不可变保证），
  中间通过 bytes(ba) 或 ba[:] 快速转换。

# padding

填充算法
> 填充字节数 = 块大小 - 待填充数据长度
> 填充字节数 = 块大小 - (待填充数据长度 % 块大小)
> 填充字节数 = 块大小 - (待填充数据长度 + 填充字节数) % 块大小

初始向量/初始值(IV, Initial Hash Value, Initialization Vector, Initialization Vector,
Initial Chaining Value): 密码学算法在开始运算前设置的起始状态或起始参数，目的是引入随机性，
确保即使相同输入也能产生不同输出，同时防止攻击者通过观察输入输出模式来破解算法。

轮常数（Round Constants）: 密码学算法（哈希函数、分组密码等）在每一轮迭代中使用的固定常量，
用于破坏对称性、增加混乱度，并防止攻击者利用轮函数的代数结构。
一般以一个固定的值开始，然后每轮迭代增加一个固定的值。

