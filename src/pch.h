#pragma once

#define PLUGIN_NAME "MShellCodePass2"

#define PASS_NAME "to-shellcode"

#include <llvm/Plugins/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Constants.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <format>


#define LOG(fmt, ...) errs() << std::format("[" PASS_NAME "] "  fmt, ##__VA_ARGS__) << "\n"


using namespace llvm;