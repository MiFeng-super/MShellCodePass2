set_xmakever("2.8.2")

-- project
set_project("MShellCodePass2")

-- version
set_version("1.0", {build = "%Y%m%d%H%M"})

-- set toolchain
set_toolchains("msvc", {vs = "2026", vs_toolset = "14.51"})

-- set language: C99, c++ standard
set_languages("cxx23", "c99")

-- set rules
add_rules("mode.debug", "mode.release", "mode.releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode"})

local llvm_root = "D:/Reverse/llvm-project/Windows"

target("MShellCodePass2")
    set_kind("shared")
    set_pcxxheader("src/pch.h")
    add_files("src/**.cpp")
    add_files("src/exports.def")
    add_includedirs("src")
    add_headerfiles("src/**.h")

    set_runtimes("MD")

    add_headerfiles(path.join(llvm_root, "include/**.h"))
    add_includedirs(path.join(llvm_root, "include"))
    add_linkdirs(path.join(llvm_root, "lib"))

    add_cxxflags("/wd4624")

    add_syslinks("ntdll")

    add_links(
        "LLVMCore",
        "LLVMSupport",
        "LLVMAnalysis",
        "LLVMTransformUtils",
        "LLVMScalarOpts",
        "LLVMInstCombine",
        "LLVMIPO",
        "LLVMIRReader",
        "LLVMBinaryFormat",
        "LLVMRemarks",
        "LLVMTargetParser",
        "LLVMDemangle",
        "LLVMBitstreamReader",
        "LLVMProfileData"
    )


target("test")
    set_kind("phony")
    add_deps("MShellCodePass2")

    local passes = "to-shellcode"
    local build_target_dir = "build/llvm_out"
    local target_cpp = "test/test.cpp"
    local target_before_ll = build_target_dir .. "/before.ll"
    local target_after_ll = build_target_dir .. "/after.ll"
    local target_exe = build_target_dir .. "/test.exe"
    local target_obj = build_target_dir .. "/test.obj"
    local target_bin = build_target_dir .. "/test.bin"

    on_build(function(target)

        os.mkdir(build_target_dir)

        local clang = llvm_root .. "/bin/clang++.exe"
        local opt = llvm_root .. "/bin/opt.exe"

        print("Generating LLVM IR...")
        os.execv(clang, {"-S", "-O3", "-emit-llvm", target_cpp, "-o", target_before_ll})
    end)

    on_run(function (target) 
        local opt = llvm_root .. "/bin/opt.exe"
        local clang = llvm_root .. "/bin/clang++.exe"
        local llc = llvm_root .. "/bin/llc.exe"
        local link = llvm_root .. "/bin/ld.exe"
        local pass_so = target:dep("MShellCodePass2"):targetfile()

        print("Run LLVM Pass...")
        os.execv(opt, {"-S", "-load-pass-plugin", pass_so, "-passes=" .. passes, target_before_ll, "-o", target_after_ll})

        print("Compiling...")
        os.execv(clang, {target_after_ll, "-O3", "-o", target_exe, "-g", "-gcodeview", "-l", "user32"})

        print("Extracting shellcode...")
        os.execv("python", {"utils/extract_shellcode.py", target_exe, target_bin})
    end)

    on_clean(function(target)
        os.rm(build_target_dir)
    end)

    after_build(function(target)
        import("core.project.project")
        import("core.base.json")

        local opt = llvm_root .. "/bin/opt.exe"
        local llvm_config = llvm_root .. "/bin/llvm-config.exe"
        local llvm_libdir = os.iorunv(llvm_config, {"--libdir"}):trim()
        local pass_so = target:dep("MShellCodePass2"):targetfile()
        local workspace = "${workspaceFolder}"

        local launch_conf = {
            version = "0.2.0",
            configurations = {
                {
                    type = "lldb",
                    request = "launch",
                    name = "Debug LLVM Pass",
                    program = opt,
                    args = {
                        "-S",
                        "-load-pass-plugin",
                        workspace .. "/" .. pass_so,
                        "-passes=" .. passes,
                        workspace .. "/" .. target_before_ll,
                        "-o",
                        workspace .. "/" .. target_after_ll
                    },
                    cwd = workspace,
                    preLaunchTask = "xmake: build",
                    env = {
                        LD_LIBRARY_PATH = llvm_libdir .. ":" .. path.directory(pass_so)
                    },
                    terminal = "integrated"
                }
            }
        }

        local vscode_dir = path.join(project.directory(), ".vscode")
        if not os.exists(vscode_dir) then os.mkdir(vscode_dir) end
        io.writefile(path.join(vscode_dir, "launch.json"), json.encode(launch_conf))
        print("launch.json updated!")
    end)

target("example")
    set_kind("binary")
    add_deps("MShellCodePass2")
    add_files("example/**.cpp")

    set_toolchains("clang-cl")