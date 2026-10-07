// Diagnostic exit breakpoint, restored before continuing; no success/state forcing.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <map>
#include <string>

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) return 2;
    std::wstring path = argv[1];
    std::wstring cwd = path.substr(0, path.find_last_of(L"\\/"));
    std::wstring command = L"\"" + path + L"\" -uid odin";
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_SHOWMINNOACTIVE;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE,
        DEBUG_ONLY_THIS_PROCESS, nullptr, cwd.c_str(), &startup, &process))
    {
        std::printf("CreateProcess error=%lu\n", GetLastError()); return 3;
    }
    DebugSetProcessKillOnExit(FALSE);
    std::map<DWORD, HANDLE> threads;
    unsigned long long base = 0;
    bool initialBreakpoint = true, exited = false;
    unsigned char originalExitByte=0;
    void* exitAddress=nullptr;
    bool exitArmed=false;
    const auto started = GetTickCount64();
    while (GetTickCount64() - started < 20000)
    {
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, 1000)) continue;
        DWORD status = DBG_CONTINUE;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            base = reinterpret_cast<unsigned long long>(event.u.CreateProcessInfo.lpBaseOfImage);
            threads[event.dwThreadId] = event.u.CreateProcessInfo.hThread;
            std::printf("PROCESS pid=%lu base=%llX\n", event.dwProcessId, base);
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
        }
        else if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
            threads[event.dwThreadId] = event.u.CreateThread.hThread;
        else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            wchar_t name[1024]{};
            if (event.u.LoadDll.hFile)
            {
                GetFinalPathNameByHandleW(event.u.LoadDll.hFile, name, 1024, 0);
                CloseHandle(event.u.LoadDll.hFile);
            }
            std::printf("MODULE base=%p %ls\n", event.u.LoadDll.lpBaseOfDll, name);
            if (wcsstr(name, L"ntdll.dll"))
            {
                auto local=GetModuleHandleW(L"ntdll.dll");
                const auto offset=reinterpret_cast<unsigned char*>(GetProcAddress(local,"NtTerminateProcess"))-reinterpret_cast<unsigned char*>(local);
                exitAddress=static_cast<unsigned char*>(event.u.LoadDll.lpBaseOfDll)+offset;
            }
        }
        else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            const auto& ex = event.u.Exception;
            std::printf("EXCEPTION code=%08lX first=%lu address=%p tid=%lu\n",
                ex.ExceptionRecord.ExceptionCode, ex.dwFirstChance,
                ex.ExceptionRecord.ExceptionAddress, event.dwThreadId);
            CONTEXT context{}; context.ContextFlags = CONTEXT_FULL;
            auto thread = threads.find(event.dwThreadId);
            if (thread != threads.end() && GetThreadContext(thread->second, &context))
            {
                std::printf("CONTEXT rip=%llX rva=%llX rsp=%llX rcx=%llX rdx=%llX\n",
                    context.Rip, context.Rip-base, context.Rsp, context.Rcx, context.Rdx);
                unsigned long long stack[128]{}; SIZE_T bytes=0;
                ReadProcessMemory(process.hProcess, reinterpret_cast<void*>(context.Rsp), stack, sizeof(stack), &bytes);
                for (unsigned i=0; i < bytes/8; ++i)
                    if (stack[i]>=base && stack[i]<base+0x168C6E00)
                        std::printf("STACK +%X mainRva=%llX\n", i*8, stack[i]-base);
            }
            if (ex.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT && initialBreakpoint)
            {
                initialBreakpoint=false;
                SIZE_T bytes=0;
                unsigned char breakpoint=0xCC;
                if(exitAddress && ReadProcessMemory(process.hProcess,exitAddress,&originalExitByte,1,&bytes) && bytes==1)
                    exitArmed=WriteProcessMemory(process.hProcess,exitAddress,&breakpoint,1,&bytes) && bytes==1;
                FlushInstructionCache(process.hProcess,exitAddress,1);
                std::printf("Exit breakpoint armed=%u\n",exitArmed);
            }
            else if (exitArmed && ex.ExceptionRecord.ExceptionAddress==exitAddress &&
                     ex.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT)
            {
                SIZE_T bytes=0;
                if(!WriteProcessMemory(process.hProcess,exitAddress,&originalExitByte,1,&bytes) || bytes!=1) return 4;
                FlushInstructionCache(process.hProcess,exitAddress,1);
                context.Rip=reinterpret_cast<DWORD64>(exitAddress);
                if(thread==threads.end() || !SetThreadContext(thread->second,&context)) return 5;
                exitArmed=false;
                std::puts("EXIT_CALL original instruction restored; continuing native call.");
            }
            else status=DBG_EXCEPTION_NOT_HANDLED;
        }
        else if (event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
        {
            std::printf("THREAD_EXIT tid=%lu code=%08lX\n", event.dwThreadId, event.u.ExitThread.dwExitCode);
            auto thread=threads.find(event.dwThreadId);
            if(thread!=threads.end()) { CloseHandle(thread->second); threads.erase(thread); }
        }
        else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            std::printf("PROCESS_EXIT code=%08lX elapsed=%llu\n", event.u.ExitProcess.dwExitCode, GetTickCount64()-started);
            exited=true;
        }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);
        std::fflush(stdout);
        if (exited) break;
    }
    if (!exited) {
        if(exitArmed) { SIZE_T bytes=0; WriteProcessMemory(process.hProcess,exitAddress,&originalExitByte,1,&bytes); FlushInstructionCache(process.hProcess,exitAddress,1); }
        DebugActiveProcessStop(process.dwProcessId); std::puts("Detached after 20 seconds; game left running.");
    }
    for (const auto& thread:threads) CloseHandle(thread.second);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return 0;
}
