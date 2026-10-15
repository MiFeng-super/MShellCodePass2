# MShellCodePass2

MShellCodePass2 是一个面向 Windows x64 的 LLVM New Pass Manager 插件。它从带有 `shellcode` 注解的入口函数出发，重写相关调用链、全局变量和外部函数调用，使目标代码能够作为独立的 `.text` 数据提取。

## 功能

- 通过 `__attribute__((annotate("shellcode")))` 识别入口函数。
- 收集入口可达的直接调用链，并为辅助函数传递统一的上下文。
- 将调用链引用的全局变量迁移到入口函数的栈上。
- 使用 DJB2 哈希和用户提供的 `resolve_api` 解析外部函数。
- 保留函数属性、调用约定、调试位置、元数据和 operand bundle。
- 支持普通 `call` 和 `invoke`，并在转换后验证 LLVM IR。
- 清理入口不可达的函数和已迁移的全局变量。
- 提供 PE `.text` 节提取脚本。

## 环境要求

- Windows x64
- Xmake 2.8.2 或更高版本
- Visual Studio 18（2026）及 MSVC 14.51 工具集
- Visual Studio 的 x64 Clang 工具
- 与 Clang 版本一致的 LLVM SDK
- Python 3；运行提取脚本时还需安装 `lief`

项目当前在 `xmake.lua` 中使用两套本地 LLVM 路径：

```lua
local llvm_root = "D:/Reverse/llvm-project/Windows-MT"
local llvm_tools_root = "D:/Reverse/llvm-project/Windows"
```

`llvm_root` 提供使用静态 CRT 构建的 LLVM 头文件、库、`opt.exe` 和 `llvm-config.exe`；`llvm_tools_root` 提供 `clang++.exe` 和 `llvm-link.exe`。示例使用的 `clang-cl.exe` 由构建脚本从 Visual Studio 安装目录自动定位。在其他环境构建前，请先将这两个变量改为实际安装路径。插件与加载它的 LLVM 工具必须使用兼容的 LLVM 版本和运行库配置。

## 构建

```powershell
xmake f -p windows -a x64 -m release
xmake
```

插件默认输出到：

```text
build/windows/x64/release/MShellCodePass2.dll
```

## 使用

### 1. 标记入口函数

```cpp
#define SHELLCODE_FUNC __attribute__((annotate("shellcode")))

SHELLCODE_FUNC void payload()
{
    // 入口代码
}
```

未标记入口的模块不会被修改。辅助函数不需要重复标记，只要能通过直接调用链从入口到达即可。

### 2. 提供外部 API 解析器

当入口调用链引用外部声明时，模块必须提供 `resolve_api`。Windows x64 下的签名为：

```cpp
uint64_t resolve_api(uint64_t hash);
```

解析器必须有函数体、不能是变参函数，并且参数和返回值宽度必须与目标指针宽度一致。Pass 会对外部函数名计算 DJB2 哈希，再将解析结果转换为相应的函数指针。没有外部调用时无需提供解析器。

### 3. 运行 Pass

```powershell
opt.exe -S `
  -load-pass-plugin build/windows/x64/release/MShellCodePass2.dll `
  -passes=to-shellcode `
  input.ll `
  -o output.ll

opt.exe -passes=verify -disable-output output.ll
```

插件也注册在 LLVM 的 `OptimizerLast` 扩展点，可通过 Clang 的 pass-plugin 机制加入优化流水线。

## 示例

`example/` 展示了跨源文件调用、全局变量迁移和结果校验。构建脚本会生成各源文件的 LLVM IR，将其合并后执行 Pass，最后链接为可执行文件。

```powershell
xmake build example
xmake run example
```

主要输出：

```text
build/example/module.ll
build/example/after.ll
build/example/example.exe
```

更精简的 Pass 与提取流程可通过 `test` 目标运行：

```powershell
python -m pip install lief
xmake build test
xmake run test
```

主要输出：

```text
build/llvm_out/before.ll
build/llvm_out/after.ll
build/llvm_out/test.dll
build/llvm_out/test.bin
```

## 已知限制

- 仅面向当前构建配置中的 Windows x64 目标。
- 入口调用链应使用可静态确定目标的直接调用；`callbr` 会被拒绝。
- 调用链内的函数指针不得逃逸到无法安全重写的位置。
- Pass 会删除标记入口不可达的函数；需要保留的代码必须从入口可达。
- 多源文件代码需要先使用 `llvm-link` 合并到同一个模块。
- 外部 API 解析器只按导出名称哈希，序号导出和转发导出的具体处理由解析器实现。

## 项目结构

```text
src/                       Pass 插件实现
src/shellcode/             调用链、全局状态和常量重写逻辑
example/                   跨文件示例
test/                      综合测试输入
utils/extract_shellcode.py PE .text 节提取脚本
xmake.lua                  构建、示例和测试流程
```
