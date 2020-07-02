# risetek.lq
Light Quic

### 开发环境 ###
* sudo apt-get install libncurses5-dev libncursesw5-dev

### 编程规范 ###
* 等于 0 （NO_ERROR）的状态返回值表示执行正常/正确。
* 小于 0 的状态返回值表示返回的错误值定义是系统定义，通常是<errno.h>中的定义。
* 大于 0 的状态返回值表示返回的错误值定义是QUIC协议给出的定义。