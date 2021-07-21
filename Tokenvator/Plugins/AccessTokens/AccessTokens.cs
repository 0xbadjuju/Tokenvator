using System;
using System.Collections.Generic;
using System.Security.Principal;

using Tokenvator.Resources;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Tokenvator.Plugins.AccessTokens
{
    class AccessTokens : IDisposable
    {
        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        protected IntPtr currentProcessToken;

        protected IntPtr hWorkingToken;
        protected IntPtr hWorkingThreadToken;

        protected readonly List<uint> threads = new List<uint>();

        internal delegate bool Create(IntPtr phNewToken, string newProcess, string arguments);

        public AccessTokens(IntPtr currentProcessToken)
        {        
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            this.currentProcessToken = currentProcessToken;

            hWorkingToken = new IntPtr();
            hWorkingThreadToken = new IntPtr();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hWorkingToken to currentProcessToken
        ////////////////////////////////////////////////////////////////////////////////
        public void SetWorkingTokenToSelf()
        {
            hWorkingToken = currentProcessToken;
            //Console.WriteLine("[*] Setting Working Token to Self: 0x{0}", hWorkingToken.ToString("X4"));
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hWorkingToken to hExisingToken
        ////////////////////////////////////////////////////////////////////////////////
        public void SetWorkingTokenToRemote()
        {
            hWorkingToken = hExistingToken;
            //Console.WriteLine("[*] Setting Working Token to Remote: 0x{0}", hWorkingToken.ToString("X4"));
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hWorkingToken to phNewToken
        ////////////////////////////////////////////////////////////////////////////////
        public void SetWorkingTokenToNewToken()
        {
            hWorkingToken = phNewToken;
            //Console.WriteLine("[*] Setting Working Token to New Token: 0x{0}", hWorkingToken.ToString("X4"));

        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hWorkingToken to hWorkingThreadToken
        ////////////////////////////////////////////////////////////////////////////////
        public void SetWorkingTokenToThreadToken()
        {
            hWorkingToken = hWorkingThreadToken;
            //Console.WriteLine("[*] Setting Working Token to New Token: 0x{0}", hWorkingToken.ToString("X4"));

        }

        ////////////////////////////////////////////////////////////////////////////////
        // Teturns a handle to the current working token
        ////////////////////////////////////////////////////////////////////////////////
        public IntPtr GetWorkingToken()
        {
            return hWorkingToken;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hToken to a processes primary token
        ////////////////////////////////////////////////////////////////////////////////
        public virtual bool OpenProcessToken(int processId)
        {
            /*
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if (!windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator)
                && !windowsPrincipal.IsInRole(WindowsBuiltInRole.SystemOperator))
            {
                Console.WriteLine("[-] Administrator privileges required");
                return false;
            }
            */

            IntPtr hProcess = kernel32.OpenProcess(Winnt.PROCESS_QUERY_INFORMATION, false, (uint)processId);
            if (IntPtr.Zero == hProcess)
            {
                Misc.GetWin32Error("OpenProcess");
                return false;
            }
            Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));

            if (!kernel32.OpenProcessToken(hProcess, Winnt.TOKEN_ALL_ACCESS, out hExistingToken))
            {
                if (!kernel32.OpenProcessToken(hProcess, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, out hExistingToken))
                {
                    Console.WriteLine(" [-] Unable to Open Process Token");
                    Misc.GetWin32Error("OpenProcessToken");
                    kernel32.CloseHandle(hProcess);
                    return false;
                }
            }
            Console.WriteLine("[*] Recieved Token Handle 0x{0}", hExistingToken.ToString("X4"));
            kernel32.CloseHandle(hProcess);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // List all process threads
        ////////////////////////////////////////////////////////////////////////////////
        public bool ListThreads(int processId)
        {
            if (0 == processId)
            {
                processId = Process.GetCurrentProcess().Id;
            }

            IntPtr hSnapshot = kernel32.CreateToolhelp32Snapshot(TiHelp32.TH32CS_SNAPTHREAD, 0);

            if (IntPtr.Zero == hSnapshot)
            {
                Misc.GetWin32Error("CreateToolhelp32Snapshot");
                return false;
            }

            TiHelp32.tagTHREADENTRY32 threadyEntry32 = new TiHelp32.tagTHREADENTRY32()
            {
                dwSize = (uint)Marshal.SizeOf(typeof(TiHelp32.tagTHREADENTRY32))
            };

            if (!kernel32.Thread32First(hSnapshot, ref threadyEntry32))
            {
                Misc.GetWin32Error("Thread32First");
                return false;
            }

            if (threadyEntry32.th32OwnerProcessID == processId)
                threads.Add(threadyEntry32.th32ThreadID);

            while (kernel32.Thread32Next(hSnapshot, ref threadyEntry32))
            {
                if (threadyEntry32.th32OwnerProcessID == processId)
                    threads.Add(threadyEntry32.th32ThreadID);
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Opens a thread token
        ////////////////////////////////////////////////////////////////////////////////
        public bool OpenThreadToken(uint threadId, uint permissions)
        {
            IntPtr hThread = kernel32.OpenThread(ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION, false, threadId);

            if (IntPtr.Zero == hThread)
            {
                Misc.GetWin32Error("OpenThread");
                return false;
            }
            Console.WriteLine("[*] Recieved Thread Handle 0x{0}", hThread.ToString("X4"));

            bool retVal = kernel32.OpenThreadToken(hThread, permissions, false, ref hWorkingThreadToken);

            if (!retVal || IntPtr.Zero == hWorkingThreadToken)
            {
                return false;
            }
            Console.WriteLine("[*] Recieved Token Handle 0x{0}", hExistingToken.ToString("X4"));
            kernel32.CloseHandle(hThread);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a new process with the duplicated token
        ////////////////////////////////////////////////////////////////////////////////
        public bool StartProcessAsUser(string newProcess)
        {
            Create createProcess;
            if (0 == Process.GetCurrentProcess().SessionId)
                createProcess = CreateProcess.CreateProcessWithLogonW;
            else
                createProcess = CreateProcess.CreateProcessWithTokenW;
            string arguments = string.Empty;
            Misc.FindExe(ref newProcess, out arguments);

            if (!createProcess(hWorkingToken, newProcess, arguments))
            {
                return false;
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Impersonates the token from a specified processId
        ////////////////////////////////////////////////////////////////////////////////
        public virtual bool ImpersonateUser()
        {
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hWorkingToken,
                        (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                Misc.GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                Misc.GetWin32Error("ImpersonateLoggedOnUser: ");
                return false;
            }

            Console.WriteLine("[+] Operating as {0}", WindowsIdentity.GetCurrent().Name);
            return true;
        }

        ~AccessTokens()
        {

        }

        public void Dispose()
        {
            try
            {
                if (IntPtr.Zero != phNewToken)
                {                    
                    kernel32.CloseHandle(phNewToken);
                }
                if (IntPtr.Zero != hExistingToken)
                {
                    kernel32.CloseHandle(hExistingToken);
                }
                if (IntPtr.Zero != hWorkingToken && currentProcessToken != hWorkingToken)
                {
                    kernel32.CloseHandle(hWorkingToken);
                }
                if (IntPtr.Zero != hWorkingThreadToken)
                {
                    kernel32.CloseHandle(hWorkingThreadToken);
                }
            }
            catch (Exception ex)
            {
                if (!(ex is SEHException))
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }
    }
}
