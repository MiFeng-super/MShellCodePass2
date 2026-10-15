// test_payload_full.c
// CShellCodePass 综合测试用例
//
// 覆盖场景:
//   [GV-1]  字符串字面量(只读, .rdata)
//   [GV-2]  可写全局标量(int)
//   [GV-3]  可写全局数组
//   [GV-4]  零初始化全局(.bss)
//   [GV-5]  结构体全局
//   [GV-6]  函数局部 static 变量(也是全局)
//   [CHAIN] 多层调用链 entry -> A -> B -> C
//   [API]   多个外部 API,部分共享同一个名字
//   [SHARE] 多个 helper 共享同一个全局(测 ctx 透传一致性)
//   [BIG]   大字节数组(测 8 字节 chunk 化优化)
//
// 使用 SHELLCODE_FUNC 标注 entry,helpers 不标注但会被调用链拉进来
 
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stddef.h>
 
#define SHELLCODE_FUNC __attribute__((annotate("shellcode")))
 
// ============================================================
//  resolve_api 部分(和你原版一致,略写)
// ============================================================
static uint64_t gvr_djb2(const char *s) 
{
    uint64_t h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)(*s++);
    return h;
}
 
static uint64_t scan_module(BYTE *base, uint64_t target);
static uint64_t resolve_forwarder(const char *fwd);
 
uint64_t resolve_api(uint64_t target) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return 0;
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY p = head->Flink; p != head; p = p->Flink) {
        LDR_DATA_TABLE_ENTRY *e =
            CONTAINING_RECORD(p, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        BYTE *base = (BYTE *)e->DllBase;
        if (!base) continue;
        uint64_t addr = scan_module(base, target);
        if (addr) return addr;
    }
    return 0;
}
 
static uint64_t scan_module(BYTE *base, uint64_t target) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) return 0;
    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)(base + dir->VirtualAddress);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *n = (const char *)(base + names[i]);
        if (gvr_djb2(n) != target) continue;
        WORD ord = ords[i];
        DWORD rva = funcs[ord];
        BYTE *addr = base + rva;
        if (rva >= dir->VirtualAddress &&
            rva <  dir->VirtualAddress + dir->Size) {
            return resolve_forwarder((const char *)addr);
        }
        return (uint64_t)(uintptr_t)addr;
    }
    return 0;
}
 
static uint64_t resolve_forwarder(const char *fwd) {
    const char *dot = fwd;
    while (*dot && *dot != '.') dot++;
    if (*dot != '.' || !dot[1]) return 0;
    return resolve_api(gvr_djb2(dot + 1));
}
 
 
// ============================================================
//  各种全局变量(测试 GV-1 ~ GV-5)
// ============================================================
 
// [GV-1] 字符串字面量 —— 实际是 private constant,Clang 自动产生的
// 这些不会显式声明为全局,但 IR 里有 @.str / @.str.1 等
 
// [GV-2] 可写全局标量
int   g_counter = 0;
DWORD g_flags   = 0x12345678;
 
// [GV-3] 可写全局数组
char g_msg_buf[64] = "default message";
 
// [GV-4] 零初始化的大 buffer(测试 ChunkedInit + 零字段)
unsigned char g_workspace[256] = { 0 };
 
// [GV-5] 结构体全局
typedef struct {
    DWORD magic;
    DWORD size;
    char  tag[16];
} Header;
Header g_header = { 0xDEADBEEF, 256, "shellcode-v1" };
 
// [BIG] 大块字节数据(测 chunk 化压缩效果)
// 这种数据典型用法:嵌入式密钥、shellcode 模板、协议常量
const unsigned char g_key[64] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
};
 
 
// ============================================================
//  调用链 helpers(不加 SHELLCODE_FUNC)
//  这些会被 collectCallChain 拉进来,加 ctx 参数
// ============================================================
 
// [CHAIN-C] 最深层:操作 g_workspace 和 g_counter
//   - 测试 [SHARE]: 同一全局被多个函数引用
//   - 测试 [GV-2]/[GV-4]
static void deep_helper(int idx, char value) {
    if (idx >= 0 && idx < (int)sizeof(g_workspace)) {
        g_workspace[idx] = (unsigned char)value;
        g_counter++;                 // 共享变量
    }
}
 
// [CHAIN-B] 中间层:调用 deep_helper,操作 g_header
static void mid_helper(const char *src, int n) {
    g_header.size = (DWORD)n;
    for (int i = 0; i < n && i < 16; i++) {
        g_header.tag[i] = src[i];    // 写结构体字段
    }
    for (int i = 0; i < n; i++) {
        deep_helper(i, src[i]);      // 链式调用
    }
}
 
// [CHAIN-A] 顶层 helper:调用 mid_helper,直接也调用外部 API
//   - 测试 ctx 透传 entry -> A -> B -> C
static void top_helper(void) {
    g_flags |= 0x80000000;           // 修改另一个全局
 
    // 这里调用了外部 API,Pass 应该把它替换成 resolve_api
    Sleep(10);
 
    // [GV-1] 字符串字面量
    mid_helper("ctx_test_payload", 16);
 
    // [GV-6] 函数局部 static
    static int call_count = 0;
    call_count++;
    g_counter += call_count;
}
 
void test_func_escape(void)
{
    top_helper();
}
 
// ============================================================
//  入口函数
// ============================================================
SHELLCODE_FUNC void my_payload(void) {
    // [GV-1] 字符串字面量
    LoadLibraryA("user32.dll");
 
    // 直接读全局
    g_counter = 1;
    g_flags = 0xCAFEBABE;
 
    // 调用链
    top_helper();
 
    // 用到 g_msg_buf 和 g_key
    for (int i = 0; i < 16; i++) {
        g_msg_buf[i] = (char)('A' + (g_key[i] & 0x0F));
    }
    g_msg_buf[16] = '\0';
    
    test_func_escape();

    // MessageBoxA(NULL, (LPCSTR)test_func_escape, "GVRuntime", MB_OK);

    // 多次调用同一 API,测 hash 缓存(Pass 不缓存,每次都 resolve,能跑就行)
    MessageBoxA(NULL, g_msg_buf, "GVRuntime", MB_OK);
    MessageBoxA(NULL, "second box", "GVRuntime", MB_OK);
 
    // 用到 g_header(结构体)和 g_workspace[0]
    if (g_header.magic == 0xDEADBEEF && g_workspace[0] != 0) {
        MessageBoxA(NULL, "header & workspace OK", "GVRuntime", MB_OK);
    }
}
 
 
// ============================================================
//  main 不加 SHELLCODE_FUNC,普通编译
// ============================================================
int main(void) {
    my_payload();
    return 0;
}