# Calling native functions with Frida

This time I want to talk about [Frida](https://www.frida.re) and the possibility it offers in calling native OS functions from *Javascript* when instrumenting a process.

All this started because some weeks ago I was working on a project and I needed to perform some specific tasks over threads and their contexts and I found that *Frida* doesn't offer me any kind of built-in function in order to access those data structures. Well, to be fair, *Frida* has some functions that provides basic information about threads and the context but that wasn't enough in my case, I needed to access the native context and that's the main reason I'm writing this post.

I'm going to show you some theory first and then I'll show you some practical examples. The post will be mostly *Windows* oriented but the theory concepts apply for any platform.

## Table of contents

1. [Introduction](#introduction)
2. [Tools](#tools)
3. [The NativePointer class](#nativepointer)
4. [The NativeFunction class](#nativefunction)
5. [What about structs?](#whataboutstructs)
6. [Practical examples](#examples) <br/>
 6.1 [Example 1: ReadProcessMemory](#readprocessmemory1) <br/>
 6.2 [Example 2: WriteProcessMemory](#writeprocessmemory2) <br/>
 6.3 [Example 3: GetThreadContext](#getthreadcontext3) <br/>
7. [Conclusion](#conclusion)
8. [Acknowledgments](#acknowledgments)

## Introduction <a name="introduction"></a>

As I said at the beginning, some weeks ago I needed to perform a task and Frida was the framework I choose to instrument the program. At some point, I needed to access OS native data and it was when I discovered the [NativeFunction](https://www.frida.re/docs/javascript-api/#nativefunction) class.

## Tools <a name="tools"></a>

 - [Frida](https://www.frida.re/docs/installation/)
 - [Python >= 3.x](https://www.python.org/downloads/) (I use 3.7, didn't test it with older versions)
 - A text editor, my favourites are [Notepad++](https://notepad-plus-plus.org/downloads/) & [Sublime Text](https://download.sublimetext.com/Sublime%20Text%20Build%203211%20x64%20Setup.exe)
 
## The NativePointer class <a name="nativepointer"></a>

The first thing we need to know is what a [NativePointer](https://www.frida.re/docs/javascript-api/#nativepointer) is. This class allows to create an object containing a memory address. Then, we can operate over that memory address and read/write data from/to it, etc.

To create a *NativePointer* is really easy, we just need to call its constructor like this:

```javascript
var memAddr = new NativePointer('0x100000');
```

or like this:

```javascript
var memAddr = ptr('0x100000');
```

After that, the *memAddr* variable will contain a pointer to the actual address, *0x100000*.

Then, we can operate over it like this (to read an *unsigned integer*):

```javascript
var data = memAddr.readU32();
```

Check the documentation of *NativePointer* in order to get a more detailed information about all the available functions in the class.

## The NativeFunction class <a name="nativefunction"></a>

The *NativeFunction* class allows to create an actual call to a specified address inside the code. This can be a function inside a program or a function from the native OS API. Most of the [ABIs](https://en.wikipedia.org/wiki/Application_binary_interface) from the platforms supported by Frida are available (stdcall, fastcall, win64, etc).

The prototype for the *NativeFunction* is the following:

```javascript
NativeFunction(address, returnType, argTypes[, abi])
```

Here's a quick description of the parameters:

 - **address**: represents the actual address of the function we want to call. This parameter must be passed as a *NativePointer*
 - **returnType**: represents the return value returned by the function we want to call
 - **argTypes**: represent the arguments of the function we want to call. The supported types are the following: *void, pointer, int, uint, long, ulong, char, uchar, float, double, int8, uint8, int16, uint16, int32, uint32, int64, uint64 and bool*.

The following is a little example on how to use the *NativeFunction* constructor. Suppose that you want to call the [OpenThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) function, you have to do it in the following way:

```javascript

var openThreadAddr = Module.findExportByName('Kernel32.dll', 'OpenThread');
openThreadCall = new NativeFunction(openThreadAddr, 'uint32', ['uint32', 'uint32', 'uint32']);
[..]
var threadToken = openThreadCall(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, threadId);
```

The first thing we need to do is to find the address of the function we want to invoke. In this case, I use the *findExportByName* function from the [Module](https://www.frida.re/docs/javascript-api/#module) class in order to get the absolute address of the *OpenThread* function. The first parameter is the name of the module the function belongs to and the second parameter is the name of the function. The returned value is already a *NativePointer*. If no address is found, the returned value is *null*.

The next step is to use the *NativeFunction* constructor in order to create an object containing the address and parameters of the function to invoke. As I already mentioned, the first parameter we have to pass to the constructor is the address of the function to invoke in the form of a *NativePointer*. The second parameter is the *type* of the return value returned by the function. The third parameter is a list containing the types of parameters received by the function. In this case, we have a list of three *uint32* values. If you read the *MSDN* entry for the *OpenThread* function, you'll see that it receives a *DWORD* as first parameter, a *BOOL* as second parameter and another *DWORD* as third parameter. The return value is a *HANDLE* type. However, we don't have those native types in *Frida* nor *Javascript* but, in essence, we can represent them as *unsigned integers*. 

Finally, we can use the variable containing the *NativeFunction* object as an actual call to the function. In my case, I've declared some constant values to use for the *dwDesiredAccess* parameter and got the *threadId* parameter from a previous call to the *Process.enumerateThreads* from *Frida*.

## What about structs? <a name="whataboutstructs"></a>

It could be the case that we need to use a structure in a function call, what we do in that case?. *Frida* nor *Javascript* don't provide any mechanism to build native OS data structures but we can make use of a given region on memory and use the *NativePointer* class in order to build our desired structure. 

We need to allocate some space in memory and then fill it with our data. It's a little bit more of work than just declare the data as we usually do in *C/C++* but the good thing is that we can continue using complex data structures even in *Javascript* :)

Let's suppose we want to create a structure like the following and then need to pass it as a parameter to a function. We have to do it like this:

This is the *C* representation of the structure:

```c
typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

This is how we can do it in *Javascript* using *Frida's* *NativePointer*:

```javascript
const IMAGE_SIZEOF_FILE_HEADER = 20;

// allocate space for the struct
var fileHeaderStruct = Memory.alloc(IMAGE_SIZEOF_FILE_HEADER); // returns a NativePointer

// fill the struct
fileHeaderStruct.writeU16(0x014C);
fileHeaderStruct.add(0x02);
fileHeaderStruct.writeU16(0x0003);
fileHeaderStruct.add(0x04);
fileHeaderStruct.writeU32(0x5DAB5139);
fileHeaderStruct.add(0x08);
fileHeaderStruct.writeU32(0x00000000);
fileHeaderStruct.add(0x0C);
fileHeaderStruct.writeU32(0x00000000);
fileHeaderStruct.add(0x10);
fileHeaderStruct.writeU16(0x00E0);
fileHeaderStruct.add(0x12);
fileHeaderStruct.writeU16(0x0102);

// use it in a function call
myFunction(ptr(fileHeaderStruct));
```

## Practical examples <a name="examples"></a>

I've prepared three examples in order to demonstrate the use of the *NativeFunction*, *NativePointer* and structs in Frida.

These examples are really basic stuff, there isn't too much more to say about this topic but are a good starting point. 

I'll put only the *Javascript* code and the output of the script once it's executed. The rest of the code can be seen [here](https://github.com/poxyran/poxyblog/tree/master/src/code/02-11-2019-calling-native-functions-with-frida).

As a target, I just used a simple *notepad.exe* instance.

### Example 1: ReadProcessMemory <a name="readprocessmemory"></a>

```javascript
	"use strict";

	const PROCESS_VM_READ = 0x0010;
	
	var pid = %d;
	var addr = ptr('0x%x');
	var size = %d;
	
	var openProcessAddr = Module.findExportByName('Kernel32.dll', 'OpenProcess');
	console.log("[-] OpenProcess address: " + openProcessAddr.toString());
	var openProcessCall = new NativeFunction(openProcessAddr, 'uint32', ['uint32', 'uint32', 'uint32']);
	
	var readProcessMemAddr = Module.findExportByName('Kernel32.dll', 'ReadProcessMemory');
	console.log("[-] ReadProcessMemory address: " + readProcessMemAddr.toString());
	var readProcessMemCall = new NativeFunction(readProcessMemAddr, 'uint32', ['uint32', 'pointer', 'pointer', 'uint32', 'pointer']);

	var getLastErrorAddr = Module.findExportByName('Kernel32.dll', 'GetLastError');
	console.log("[-] GetLastError address: " + getLastErrorAddr.toString());
	var getLastErrorCall = new NativeFunction(getLastErrorAddr, 'uint32', []);
	
	console.log("[-] Reading memory from process with PID: " + pid.toString());
	
	var hProcess = openProcessCall(PROCESS_VM_READ, 0, pid);

	if (hProcess != 0)
	{
		console.log("[-] hProcess: " + hProcess.toString());

		var lpNumberOfBytesRead = Memory.alloc(8);
		var lpBuffer = Memory.alloc(size * 2);
		
		var retVal = readProcessMemCall(hProcess, addr, ptr(lpBuffer), size, ptr(lpNumberOfBytesRead));

		console.log("[-] ReadProcessMemory retVal: " + retVal.toString());
		
		if (retVal != 0)
		{
			console.log("[-] ReadProcessMemory read " + lpNumberOfBytesRead.readU32().toString() + " bytes from " + addr);

			console.log(hexdump(lpBuffer, { offset: 0,  length: lpNumberOfBytesRead.readU32(),  header: true, ansi: false
			}));
		}
		else
		{
			console.log("[!] ReadProcessMemory failed. GetLastError: " + getLastErrorCall().toString());
		}
	}
	else
	{
		console.log('[!] OpenProcess failed!.');
	}

```

Script output:

```
>python.exe frida-read-process-memory.py
Usage: frida-read-process-memory.py <process name or PID> <addr> <size>

>python.exe frida-read-process-memory.py 556 169F0000 100

[-] OpenProcess address: 0x7ffcb07aa1a0
[-] ReadProcessMemory address: 0x7ffcb07aafa0
[-] GetLastError address: 0x7ffcb07a6780
[-] Reading memory from process with PID: 556
[-] hProcess: 1988
[-] ReadProcessMemory retVal: 1
[-] ReadProcessMemory read 100 bytes from 0x169f0000
              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
19d988066a0  32 00 00 00 f8 3d 8d 60 28 81 a7 4a a4 28 f5 5e  2....=.`(..J.(.^
19d988066b0  49 26 72 91 00 00 08 00 0b 00 00 00 54 00 65 00  I&r.........T.e.
19d988066c0  78 00 74 00 20 00 45 00 64 00 69 00 74 00 6f 00  x.t. .E.d.i.t.o.
19d988066d0  72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  r...............
19d988066e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
19d988066f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
19d98806700  00 00 00 00                                      ....
[*] Control-D to terminate....
```

Despite the debug lines, using native calls in Frida implies a many more lines of code than just using its built-in functions. The same task can be done by just using one or two lines of code:

```javascript
		var buf = Memory.readByteArray(ptr('0x%x'), %d);
		 console.log(hexdump(buf, {
	 		offset: 0, 
		 		length: %d, 
		 		header: true,
		 		ansi: false
		 	}));
```

**Important Note**: the use of *Memory.read/write* is going to be deprecated. Use *NativePointer* instead:

```javascript
var mem = new NativePointer(address);
var buf = mem.readByteArray(size);
```

### Example 2: WriteProcessMemory <a name="writeprocessmemory"></a>

```javascript
	"use strict";
	
	const PROCESS_VM_WRITE = 0x0020;
	const PROCESS_VM_OPERATION = 0x0008;
	
	var pid = %d;
	var addr = ptr('0x%x');
	var bytes = %s;
	
	var openProcessAddr = Module.findExportByName('Kernel32.dll', 'OpenProcess');
	console.log("[-] OpenProcess address: " + openProcessAddr.toString());
	var openProcessCall = new NativeFunction(openProcessAddr, 'uint32', ['uint32', 'uint32', 'uint32']);
	
	var writeProcessMemoryAddr = Module.findExportByName('Kernel32.dll', 'WriteProcessMemory');
	console.log("[-] ReadProcessMemory address: " + writeProcessMemoryAddr.toString());
	var writeProcessMemoryCall = new NativeFunction(writeProcessMemoryAddr, 'uint32', ['uint32', 'pointer', 'pointer', 'uint32', 'pointer']);

	var getLastErrorAddr = Module.findExportByName('Kernel32.dll', 'GetLastError');
	console.log("[-] GetLastError address: " + getLastErrorAddr.toString());
	var getLastErrorCall = new NativeFunction(getLastErrorAddr, 'uint32', []);
	
	console.log("[-] Reading memory from process with PID: " + pid.toString());
	
	var hProcess = openProcessCall(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);

	if (hProcess != 0)
	{
		console.log("[-] hProcess: " + hProcess.toString());

		console.log("[-] Bytes to write: " + bytes);
		
		var lpNumberOfBytesWritten = Memory.alloc(8);
		var lpBuffer = Memory.alloc(bytes.length * 2);
		lpBuffer.writeByteArray(bytes);

		var retVal = writeProcessMemoryCall(hProcess, addr, lpBuffer, bytes.length, ptr(lpNumberOfBytesWritten));
		
		console.log("[-] WriteProcessMemory retVal: " + retVal.toString());
		
		if (retVal != 0)
		{
			console.log("[-] WriteProcessMemory wrote " + lpNumberOfBytesWritten.readU32().toString() + " bytes from " + addr);
		}
		else
		{
			console.log("[!] WriteProcessMemory failed. GetLastError: " + getLastErrorCall().toString());
		}
	}
	else
	{
		console.log('[!] OpenProcess failed!.');
	}

```

Script output:

```
>python.exe frida-write-process-memory.py"
Usage: frida-write-process-memory.py <process name or PID> <addr> <bytes in the form of "41 42 43 44">

>python.exe frida-write-process-memory.py" 556 0x169f0000 "41 42 43 44"
[-] OpenProcess address: 0x7ffcb07aa1a0
[-] ReadProcessMemory address: 0x7ffcb07c6c50
[-] GetLastError address: 0x7ffcb07a6780
[-] Reading memory from process with PID: 556
[-] hProcess: 1748
[-] Bytes to write: 65,66,67,68
[-] WriteProcessMemory retVal: 1
[-] WriteProcessMemory wrote 4 bytes from 0x169f0000
[*] Control-D to terminate....
```

If we use the previous example to check if the bytes were written, we can see the following output:

```
>python.exe frida-read-process-memory.py" 556 169F0000 100
[-] OpenProcess address: 0x7ffcb07aa1a0
[-] ReadProcessMemory address: 0x7ffcb07aafa0
[-] GetLastError address: 0x7ffcb07a6780
[-] Reading memory from process with PID: 556
[-] hProcess: 1336
[-] ReadProcessMemory retVal: 1
[-] ReadProcessMemory read 100 bytes from 0x169f0000
              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
19d989243c0  41 42 43 44 f8 3d 8d 60 28 81 a7 4a a4 28 f5 5e  ABCD.=.`(..J.(.^
19d989243d0  49 26 72 91 00 00 08 00 0b 00 00 00 54 00 65 00  I&r.........T.e.
19d989243e0  78 00 74 00 20 00 45 00 64 00 69 00 74 00 6f 00  x.t. .E.d.i.t.o.
19d989243f0  72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  r...............
19d98924400  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
19d98924410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
19d98924420  00 00 00 00                                      ....
[*] Control-D to terminate....
```

Yeah!. Bytes were successfully written to the specified memory location. You can see the **ABCD** string at the beginning of the memory region.

There's is one detail in the implementation. At my first try, *WriteProcessMemory* wasn't working, it was failing. The reason was that I was using only **PROCESS_VM_WRITE** in the **dwDesiredAccess** parameter in the call to *OpenProcess* when in fact you also need **PROCESS_VM_OPERATION** according to the *WriteProcessMemory MSDN* documentation (see *Remarks*).

### Example 3: GetThreadContext <a name="getthreadcontext"></a>

The third example is to read the thread context structure from the first thread running in the specified process.

I won't go into much details but, basically, I tried to get the data from the first thread context running in the specified process. The thread context is defined as follow (extracted from *Windbg's* output):

```
0:001> dt nt!_CONTEXT
ntdll!_CONTEXT
   +0x000 P1Home           : Uint8B
   +0x008 P2Home           : Uint8B
   +0x010 P3Home           : Uint8B
   +0x018 P4Home           : Uint8B
   +0x020 P5Home           : Uint8B
   +0x028 P6Home           : Uint8B
   +0x030 ContextFlags     : Uint4B
   +0x034 MxCsr            : Uint4B
   +0x038 SegCs            : Uint2B
   +0x03a SegDs            : Uint2B
   +0x03c SegEs            : Uint2B
   +0x03e SegFs            : Uint2B
   +0x040 SegGs            : Uint2B
   +0x042 SegSs            : Uint2B
   +0x044 EFlags           : Uint4B
   +0x048 Dr0              : Uint8B
   +0x050 Dr1              : Uint8B
   +0x058 Dr2              : Uint8B
   +0x060 Dr3              : Uint8B
   +0x068 Dr6              : Uint8B
   +0x070 Dr7              : Uint8B
   +0x078 Rax              : Uint8B
   +0x080 Rcx              : Uint8B
   +0x088 Rdx              : Uint8B
   +0x090 Rbx              : Uint8B
   +0x098 Rsp              : Uint8B
   +0x0a0 Rbp              : Uint8B
   +0x0a8 Rsi              : Uint8B
   +0x0b0 Rdi              : Uint8B
   +0x0b8 R8               : Uint8B
   +0x0c0 R9               : Uint8B
   +0x0c8 R10              : Uint8B
   +0x0d0 R11              : Uint8B
   +0x0d8 R12              : Uint8B
   +0x0e0 R13              : Uint8B
   +0x0e8 R14              : Uint8B
   +0x0f0 R15              : Uint8B
   +0x0f8 Rip              : Uint8B
   +0x100 FltSave          : _XSAVE_FORMAT
   +0x100 Header           : [2] _M128A
   +0x120 Legacy           : [8] _M128A
   +0x1a0 Xmm0             : _M128A
   +0x1b0 Xmm1             : _M128A
   +0x1c0 Xmm2             : _M128A
   +0x1d0 Xmm3             : _M128A
   +0x1e0 Xmm4             : _M128A
   +0x1f0 Xmm5             : _M128A
   +0x200 Xmm6             : _M128A
   +0x210 Xmm7             : _M128A
   +0x220 Xmm8             : _M128A
   +0x230 Xmm9             : _M128A
   +0x240 Xmm10            : _M128A
   +0x250 Xmm11            : _M128A
   +0x260 Xmm12            : _M128A
   +0x270 Xmm13            : _M128A
   +0x280 Xmm14            : _M128A
   +0x290 Xmm15            : _M128A
   +0x300 VectorRegister   : [26] _M128A
   +0x4a0 VectorControl    : Uint8B
   +0x4a8 DebugControl     : Uint8B
   +0x4b0 LastBranchToRip  : Uint8B
   +0x4b8 LastBranchFromRip : Uint8B
   +0x4c0 LastExceptionToRip : Uint8B
   +0x4c8 LastExceptionFromRip : Uint8B
```

I enumerate all the threads running in the process using the *Process.enumerateThreads()*. If you want to do it natively, you should use **NtQuerySystemInformation** with **SystemProcessesAndThreadsInformation** and then iterate over the **SYSTEM_PROCESS_INFORMATION->SYSTEM_PROCESS_INFORMATION[]** array. In my case, this part wasn't important  for my task so I decided to keep it as simple as possible and that basically why I used Frida's built-in functions. 

Then, *OpenThread* is used to open a handle to the specified thread. You can see that, previous to the *GetThreadContext* call, I use *Memory.alloc* in order to allocate some space for the structure I'm going to read with the aforementioned function. 

One important thing is to set the *ContextFlag* field with the correct values in order to get the necessary amount of details in the structure. This value must be set at offset *0x30*.

The final step is just a matter of calling *GetThreadContext* and use the function from the *NativePointer* class in order to read the values from the returned data.

Script code:

```javascript

	"use strict";

	const THREAD_SUSPEND_RESUME = 0x0002;
	const THREAD_GET_CONTEXT = 0x0008;
	const THREAD_QUERY_INFORMATION = 0x0040;
	const CONTEXT_FULL = 0x10007;
	const CONTEXT_DEBUG_REGISTERS = 0x10010;
	
	var threads = new Array();

	console.log("[-] Enumerating threads..");
	threads = Process.enumerateThreads();
	
	console.log("[-] Working over threadId: " + threads[0]['id'].toString(16));
	
	var openThreadAddr = Module.findExportByName('Kernel32.dll', 'OpenThread');
	console.log("[-] OpenThread address: " + openThreadAddr.toString());
	
	var openThreadCall = new NativeFunction(openThreadAddr, 'uint32', ['uint32', 'uint32', 'uint32']);

	var closeHandleAddr = Module.findExportByName('Kernel32.dll', 'CloseHandle');
	var closeHandleCall = new NativeFunction(closeHandleAddr, 'uint32', ['uint32']);
	
	console.log("[-] CloseHandle addr: " + closeHandleAddr.toString());
	
	console.log("[-] Calling OpenThread..");
	
	var threadToken = openThreadCall(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, parseInt(threads[0]['id']));

	if(threadToken)
	{
		console.log("[-] hThread: " + threadToken.toString());
		
		var getThreadContextAddr = Module.findExportByName('Kernel32.dll', 'GetThreadContext');
		console.log("[-] GetThreadContext addr: " + getThreadContextAddr.toString());
		
		var getThreadContextCall = new NativeFunction(getThreadContextAddr, 'uint32', ['uint32', 'pointer']);
		
		var tContext64 = Memory.alloc(2048);
		
		var contextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		
		console.log("[-] Value of CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS: " + contextFlags.toString(16));
		
		tContext64.add(0x30).writeU32(contextFlags);
		
		console.log("[-] Calling GetThreadContext..");
		var hResult = getThreadContextCall(threadToken, ptr(tContext64));
		
		console.log("[-] GetThreadContext returned: " + hResult.toString());
		
		if (hResult != 0)
		{
			console.log("[-] Context values");
			
			// reading the place holders
			console.log("--> P1Home: " + tContext64.readU64());
			console.log("--> P2Home: " + tContext64.add(0x08).readU64().toString(16));
			console.log("--> P3Home: " + tContext64.add(0x10).readU64().toString(16));
			console.log("--> P4Home: " + tContext64.add(0x18).readU64().toString(16));
			console.log("--> P5Home: " + tContext64.add(0x20).readU64().toString(16));
			console.log("--> P6Home: " + tContext64.add(0x28).readU64().toString(16));
			
			// ContexFlags
			console.log("--> ContextFlags: " + tContext64.add(0x30).readU32().toString(16));
			
			// Segment registers
			console.log("--> MxCsr: " + tContext64.add(0x34).readU32().toString(16));
			console.log("--> SegCs: " + tContext64.add(0x38).readU16().toString(16));
			console.log("--> SegDs: " + tContext64.add(0x3A).readU16().toString(16));
			console.log("--> SegEs: " + tContext64.add(0x3C).readU16().toString(16));
			console.log("--> SegFs: " + tContext64.add(0x3E).readU16().toString(16));
			console.log("--> SegGs: " + tContext64.add(0x40).readU16().toString(16));
			console.log("--> SegSs: " + tContext64.add(0x42).readU16().toString(16));
			console.log("--> EFlags: " + tContext64.add(0x44).readU32().toString(16));
			
			// DRx registers
			console.log("--> Dr0: " + tContext64.add(0x48).readU64().toString(16));
			console.log("--> Dr1: " + tContext64.add(0x50).readU64().toString(16));
			console.log("--> Dr2: " + tContext64.add(0x58).readU64().toString(16));
			console.log("--> Dr3: " + tContext64.add(0x60).readU64().toString(16));
			console.log("--> Dr6: " + tContext64.add(0x68).readU64().toString(16));
			console.log("--> Dr7: " + tContext64.add(0x70).readU64().toString(16));
			
			// General purpose registers
			console.log("--> Rax: " + tContext64.add(0x78).readU64().toString(16));
			console.log("--> Rcx: " + tContext64.add(0x80).readU64().toString(16));
			console.log("--> Rdx: " + tContext64.add(0x88).readU64().toString(16));
			console.log("--> Rbx: " + tContext64.add(0x90).readU64().toString(16));
			console.log("--> Rsp: " + tContext64.add(0x98).readU64().toString(16));
			console.log("--> Rbp: " + tContext64.add(0xA0).readU64().toString(16));
			console.log("--> Rsi: " + tContext64.add(0xA8).readU64().toString(16));
			console.log("--> Rdi: " + tContext64.add(0xB0).readU64().toString(16));
			console.log("--> R8: " + tContext64.add(0xB8).readU64().toString(16));
			console.log("--> R9: " + tContext64.add(0xC0).readU64().toString(16));
			console.log("--> R10: " + tContext64.add(0xC8).readU64().toString(16));
			console.log("--> R11: " + tContext64.add(0xD0).readU64().toString(16));
			console.log("--> R12: " + tContext64.add(0xD8).readU64().toString(16));
			console.log("--> R13: " + tContext64.add(0xE0).readU64().toString(16));
			console.log("--> R14: " + tContext64.add(0xE8).readU64().toString(16));
			console.log("--> R15: " + tContext64.add(0xF0).readU64().toString(16));
			console.log("--> Rip: " + tContext64.add(0xF8).readU64().toString(16));			
		}
		else
		{
			console.log("[!] Error: GetThreadContext failed.");
		}
		
		console.log("[-] Closing thread token..");
		hResult = closeHandleCall(threadToken);
		if (hResult == 0)
			console.log("[!] CloseHandle faile.");
		console.log("Done.");
	}
	else
	{
		console.log("[!] OpenThread failed!");
	}
```

Script output:

```
>python.exe frida-read-thread-context.py" 556
[-] Enumerating threads..
[-] Working over threadId: 4f0
[-] OpenThread address: 0x7ffcb07abcd0
[-] CloseHandle addr: 0x7ffcb07b1e10
[-] Calling OpenThread..
[-] hThread: 1680
[-] GetThreadContext addr: 0x7ffcb07aeae0
[-] Value of CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS: 10017
[-] Calling GetThreadContext..
[-] GetThreadContext returned: 1
[-] Context values
--> P1Home: 0
--> P2Home: 0
--> P3Home: 0
--> P4Home: 0
--> P5Home: 0
--> P6Home: 0
--> ContextFlags: 100017
--> MxCsr: 0
--> SegCs: 33
--> SegDs: 2b
--> SegEs: 2b
--> SegFs: 53
--> SegGs: 2b
--> SegSs: 2b
--> EFlags: 244
--> Dr0: 0
--> Dr1: 0
--> Dr2: 0
--> Dr3: 0
--> Dr6: 0
--> Dr7: 0
--> Rax: 1009
--> Rcx: 7799b1f650
--> Rdx: 0
--> Rbx: 7799b1f650
--> Rsp: 7799b1f598
--> Rbp: 7799b1f669
--> Rsi: 0
--> Rdi: 7ff77f970000
--> R8: 62c7
--> R9: 2e1eb2
--> R10: 19d96f00000
--> R11: 1eb2
--> R12: 0
--> R13: 0
--> R14: 7ff77f970000
--> R15: 1
--> Rip: 7ffcaee41164
[-] Closing thread token..
Done.
[*] Control-D to terminate....
```
One small detail about the *write* methods. The *write* methods return **this** (similar to *self* in Python), which means we can chain calls, e.g: **p.writeU32(1234).add(4).writeU16(4321).add(2).writeUtf8String('test')** (if you want, you can also break across multiple lines for readability).

## Conclusion <a name="conclusion"></a>

As you have noticed, using native calls in *Frida* complicates a little bit more the code and stuff, especially when you have to deal with native data structures. These were just basic examples but keep in mind that you'll maybe have to work with nested structures at some point and that would surely complicates things even more. 

The good thing is that being able to call native functions from *Frida* is a great feature. You are not limited only to what *Frida* has to offer in a built-in manner, you can go further and use OS native calls and data structures from it which I think is awesome.

## Acknowledgments <a name="acknowledgments"></a>

To [oleavr](https://twitter.com/oleavr) for its awesome framework and being so kind answering always to all my questions.
