import sys
import frida

def on_message(message, data):
	print ("[%s] -> %s" % (message, data))

def make_ba(bytes):
	return '[%s]' % ','.join(["0x%02x" % int(x, 16) for x in bytes.split(' ')])

def main(target_process, addr, bytes):
	session = frida.attach(target_process)
	script = session.create_script("""
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

""" % (target_process, addr, bytes))

	script.on('message', on_message)
	script.load()
	print('[*] Control-D to terminate....')
	sys.stdin.read()
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print ('Usage: %s <process name or PID> <addr> <bytes in the form of "41 42 43 44">' % __file__)
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	addr, bytes = int(sys.argv[2], 16), sys.argv[3]
	
	main(target_process, addr, make_ba(bytes))