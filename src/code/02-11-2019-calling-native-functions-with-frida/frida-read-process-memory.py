import sys
import frida

def on_message(message, data):
	print ("[%s] -> %s" % (message, data))

def main(target_process, addr, size):
	session = frida.attach(target_process)
	script = session.create_script("""
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

""" % (target_process, addr, size))

	script.on('message', on_message)
	script.load()
	
	print('[*] Control-D to terminate....')
	sys.stdin.read()
	
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print ('Usage: %s <process name or PID> <addr> <size>' % __file__)
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	addr, size = int(sys.argv[2], 16), int(sys.argv[3])
	main(target_process, addr, size)