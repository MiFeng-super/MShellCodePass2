#include "pch.h"

#include "shellcode/shellcode.h"

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() 
{
    return {
        LLVM_PLUGIN_API_VERSION, PLUGIN_NAME, LLVM_VERSION_STRING,
        [](PassBuilder& PB)
        {
            PB.registerPipelineParsingCallback([](StringRef Name, ModulePassManager& MPM, ArrayRef<PassBuilder::PipelineElement>) -> bool 
            {
                if (Name == PASS_NAME) 
                {
                    MPM.addPass(ToShellCodePass());
                    return true;
                }
                
                return false;
            });

            PB.registerOptimizerLastEPCallback([](
                ModulePassManager& MPM,
                OptimizationLevel,
                ThinOrFullLTOPhase
            )
            {
                MPM.addPass(ToShellCodePass());
            });
        }
    };
}
