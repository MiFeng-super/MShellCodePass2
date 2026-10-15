# clang-cl 示例

使用 Visual Studio 18（2026）安装的 x64 clang-cl 编译，Pass 插件由 VS 18 的 MSVC 工具链构建：

```powershell
xmake f -p windows -a x64 -m release
xmake -v example
xmake run example
```

`xmake.lua` 自动定位 VS 18 的 `VC/Tools/Llvm/x64/bin/clang-cl.exe`。构建时先为
每个源文件生成 LLVM IR，再通过 `llvm-link` 合并模块，并使用 `opt` 显式运行
`to-shellcode`，插件不会成为 example 的运行时依赖。VS clang-cl 与
`llvm_root` 指向的 LLVM SDK 版本须一致。

VS 18 的 LLVM 工具使用静态 CRT 和 rpmalloc。因此插件使用独立的
D:/Reverse/llvm-project/Windows-MT LLVM SDK；该 SDK 以 /MT、
LLVM_ENABLE_RPMALLOC=ON、RTTI ON、assertions OFF 构建，避免插件与宿主跨分配器释放内存。

插件通过 LLVM 22 的 OptimizerLast 扩展点自动运行 to-shellcode，也保留
opt -passes=to-shellcode 的显式入口。
构建输出应包含 `[to-shellcode] Found entry function: main`。

示例将全局变量传入辅助函数，并以返回值检查转换后的计算结果：成功返回 0，失败返回 1。
由于 Pass 会裁剪标注入口不可达的函数，`main` 本身使用 `SHELLCODE_FUNC` 标注。
示例没有外部 API 调用，因此不需要 `resolve_api`。
