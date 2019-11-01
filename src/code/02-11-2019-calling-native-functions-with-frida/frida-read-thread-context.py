# frida-read-thread-context

import sys
import frida

def on_message(message, data):
	print ("[%s] -> %s" % (message, data))

def main(pid):
	session = frida.attach(pid)
	script = session.create_script("""

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
""")

	script.on('message', on_message)
	script.load()
	print('[*] Control-D to terminate....')
	sys.stdin.read()
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print ('Usage: %s <PID>' % __file__)
		sys.exit(1)
		
	main(int(sys.argv[1]))
