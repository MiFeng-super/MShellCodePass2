#include <Windows.h>
#include "utils/utils.hpp"

#define SHELLCODE_FUNC __attribute__((annotate("shellcode")))

static volatile unsigned g_value = 21;

__attribute__((noinline)) static unsigned double_value()
{
    return g_value * 2;
}

SHELLCODE_FUNC int main()
{
    int result = utils::add(1, 2);
    if (result != 3)
    {
        return 1;
    }
    // Sleep(1000);
    return double_value() == 42 ? 0 : 1;
}
