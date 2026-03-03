// 最小化空 SO，用于 debug-inject so-empty 模式
// 仅包含一个空函数，没有任何框架符号、字符串或 .init_array 逻辑
// 用途：隔离测试 V-OS 检测的是 memfd 映射还是 SO 内容
