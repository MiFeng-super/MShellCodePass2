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

local llvm_root = "D:/Reverse/llvm-project/Windows-MT"
local llvm_tools_root = "D:/Reverse/llvm-project/Windows"

target("MShellCodePass2")
    set_kind("shared")
    set_policy("build.fence", true)
    set_pcxxheader("src/pch.h")
    add_files("src/**.cpp")
    add_files("src/exports.def")
    add_includedirs("src")
    add_headerfiles("src/**.h")

    set_runtimes("MT")

    add_headerfiles(path.join(llvm_root, "include/**.h"))
    add_includedirs(path.join(llvm_root, "include"))
    add_linkdirs(path.join(llvm_root, "lib"))

    add_cxxflags("/wd4624")
    add_shflags("/include:malloc", {force = true})

    add_syslinks("psapi", "shell32", "ole32", "uuid", "advapi32", "ws2_32", "ntdll")

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
    local target_dll = build_target_dir .. "/test.dll"
    local target_obj = build_target_dir .. "/test.obj"
    local target_bin = build_target_dir .. "/test.bin"

    on_build(function(target)

        os.mkdir(build_target_dir)

        local clang = llvm_tools_root .. "/bin/clang++.exe"
        local opt = llvm_root .. "/bin/opt.exe"

        print("Generating LLVM IR...")
        os.execv(clang, {"-S", "-O3", "-emit-llvm", target_cpp, "-o", target_before_ll})
    end)

    on_run(function (target) 
        local opt = llvm_root .. "/bin/opt.exe"
        local clang = llvm_tools_root .. "/bin/clang++.exe"
        local pass_so = target:dep("MShellCodePass2"):targetfile()

        print("Run LLVM Pass...")
        os.execv(opt, {"-S", "-load-pass-plugin", pass_so, "-passes=" .. passes, target_before_ll, "-o", target_after_ll})

        print("Verifying transformed LLVM IR...")
        os.execv(opt, {"-passes=verify", "-disable-output", target_after_ll})

        print("Compiling...")
        os.execv(clang, {target_after_ll, "-shared", "-O3", "-o", target_dll, "-g", "-gcodeview"})

        print("Extracting shellcode...")
        os.execv("python", {"utils/extract_shellcode.py", target_dll, target_bin})
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
    set_kind("phony")
    add_deps("MShellCodePass2")
    set_toolchains("clang-cl", {vs = "2026", vs_toolset = "14.51"})
    set_runtimes("MD")
    set_policy("build.ccache", false)

    local example_build_dir = "build/example"
    local example_module = example_build_dir .. "/module.ll"
    local example_after_ll = example_build_dir .. "/after.ll"
    local example_bin = example_build_dir .. "/example.exe"

    on_load(function(target)
        import("detect.sdks.find_vstudio")

        local installations = find_vstudio({toolset = "14.51"}) or {}
        local vs = assert(installations["2026"], "Visual Studio 18 (2026) is required for example")
        assert(target:is_arch("x64"), "example requires x64 to match the pass plugin")
        local vcvars = assert(vs.vcvarsall.x64, "Visual Studio 18 x64 build tools are required")
        local clang_cl = path.join(vcvars.VCInstallDir, "Tools/Llvm/x64/bin/clang-cl.exe")
        assert(os.isfile(clang_cl), "Install the Visual Studio 18 C++ Clang tools: " .. clang_cl)

        target:set("toolset", "cc", "clang_cl@" .. clang_cl)
        target:set("toolset", "cxx", "clang_cl@" .. clang_cl)
        target:data_set("example.clang_cl", clang_cl)
    end)

    on_config(function(target)
        local clang_cl = target:data("example.clang_cl")
        local clang_version = os.iorunv(clang_cl, {"--version"}):match("clang version ([%d.]+)")
        local llvm_version = os.iorunv(path.join(llvm_root, "bin/llvm-config.exe"), {"--version"}):trim()
        assert(clang_version == llvm_version,
            "LLVM version mismatch: VS clang-cl is " .. tostring(clang_version) .. ", pass SDK is " .. llvm_version)
    end)

    on_build(function(target)
        os.mkdir(example_build_dir)

        local clang_cl = target:data("example.clang_cl")
        local llvm_link = path.join(llvm_tools_root, "bin/llvm-link.exe")
        local opt = path.join(llvm_root, "bin/opt.exe")
        local pass_dll = path.absolute(target:dep("MShellCodePass2"):targetfile())
        local ir_files = {}

        for index, source in ipairs(os.files("example/**.cpp")) do
            local ir = path.join(example_build_dir, "input_" .. index .. ".ll")
            print("Generating LLVM IR: " .. source)
            os.execv(clang_cl, {"/O2", "/clang:-S", "/clang:-emit-llvm", "/clang:-o" .. ir, source})
            table.insert(ir_files, ir)
        end

        print("Linking LLVM modules...")
        local link_args = {"-S"}
        for _, ir in ipairs(ir_files) do
            table.insert(link_args, ir)
        end
        table.insert(link_args, "-o")
        table.insert(link_args, example_module)
        os.execv(llvm_link, link_args)

        print("Running LLVM pass on unified module...")
        os.execv(opt, {"-S", "-load-pass-plugin", pass_dll, "-passes=to-shellcode", example_module, "-o", example_after_ll})
        os.execv(opt, {"-passes=verify", "-disable-output", example_after_ll})

        print("Linking example executable...")
        os.execv(clang_cl, {example_after_ll, "/Fe:" .. path.absolute(example_bin)})
    end)

    on_run(function()
        os.execv(path.absolute(example_bin), {})
    end)
