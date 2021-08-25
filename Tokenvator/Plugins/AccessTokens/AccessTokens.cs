using System;
using System.Collections.Generic;
using System.Security.Principal;

using Tokenvator.Resources;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;
//using MonkeyWorks.Unmanaged.Libraries.DInvoke;

using DInvoke.DynamicInvoke;

using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security;

namespace Tokenvator.Plugins.AccessTokens
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    class AccessTokens : IDisposable
    {
        private bool Disposed = false;

        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        protected IntPtr currentProcessToken;

        protected IntPtr hWorkingToken;
        protected IntPtr hWorkingThreadToken;

        protected readonly List<uint> threads = new List<uint>();

        internal delegate bool Create(IntPtr phNewToken, string newProcess, string arguments);

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="currentProcessToken"></param>
        public AccessTokens(IntPtr currentProcessToken)
        {        
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            this.currentProcessToken = currentProcessToken;

            hWorkingToken = new IntPtr();
            hWorkingThreadToken = new IntPtr();
        }

        #region Get/Set
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
        #endregion

        /// <summary>
        /// Opens a process Token
        /// Converted to Dinvoke Syscalls 
        /// </summary>
        /// <param name="processId"></param>
        /// <returns></returns>
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public virtual bool OpenProcessToken(int processId)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Open a limited handle to the process via a syscall stub
            // IntPtr hProcess = kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, false, (uint)processId);
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hNtOpenProcess = Generic.GetSyscallStub("NtOpenProcess");
            MonkeyWorks.ntdll.NtOpenProcess fSyscallNtOpenProcess = (MonkeyWorks.ntdll.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(hNtOpenProcess, typeof(MonkeyWorks.ntdll.NtOpenProcess));

            IntPtr hProcess = new IntPtr();
            MonkeyWorks.ntdll.OBJECT_ATTRIBUTES objectAttributes = new MonkeyWorks.ntdll.OBJECT_ATTRIBUTES();
            MonkeyWorks.ntdll.CLIENT_ID clientId = new MonkeyWorks.ntdll.CLIENT_ID();
            clientId.UniqueProcess = new IntPtr(processId);

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtOpenProcess(ref hProcess, ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, ref objectAttributes, ref clientId);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtOpenProcess Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtOpenProcess", ntRetVal);
                return false;
            }
            Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            // Open a handle to the process token
            // bool retVal = kernel32.OpenProcessToken(hProcess, (ulong)Winnt.TOKEN_ALL_ACCESS, out hExistingToken)
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hNtOpenProcessToken = Generic.GetSyscallStub("NtOpenProcessToken");
            MonkeyWorks.ntdll.NtOpenProcessToken fSyscallNtOpenProcessToken = (MonkeyWorks.ntdll.NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(hNtOpenProcessToken, typeof(MonkeyWorks.ntdll.NtOpenProcessToken));

            try
            {
                ntRetVal = fSyscallNtOpenProcessToken(hProcess, Winnt.TOKEN_ALL_ACCESS, ref hExistingToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtOpenProcessToken Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtOpenProcessToken", ntRetVal);

                try
                {
                    ntRetVal = fSyscallNtOpenProcessToken(hProcess, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, ref hExistingToken);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] NtOpenProcessToken Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    return false;
                }

                if (0 != ntRetVal)
                {
                    Console.WriteLine(" [-] Unable to Open Process Token");
                    Misc.GetNtError("NtOpenProcessToken", ntRetVal);
                    CloseHandle(hProcess);
                    return false;
                }
            }
            Console.WriteLine("[*] Recieved Token Handle 0x{0}", hExistingToken.ToString("X4"));
            CloseHandle(hProcess);
            return true;
        }

        /// <summary>
        /// List all threads for a given process
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="processId"></param>
        /// <returns></returns>
        public bool ListThreads(int processId)
        {
            if (0 == processId)
            {
                processId = Process.GetCurrentProcess().Id;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // Create a snapshot of all system threads that can be walked through
            // IntPtr hSnapshot = kernel32.CreateToolhelp32Snapshot(TiHelp32.TH32CS_SNAPTHREAD, 0);
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hKernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hCreateToolhelp32Snapshot = Generic.GetExportAddress(hKernel32, "CreateToolhelp32Snapshot");
            MonkeyWorks.kernel32.CreateToolhelp32Snapshot fCreateToolhelp32Snapshot = (MonkeyWorks.kernel32.CreateToolhelp32Snapshot)Marshal.GetDelegateForFunctionPointer(hCreateToolhelp32Snapshot, typeof(MonkeyWorks.kernel32.CreateToolhelp32Snapshot));
            IntPtr hSnapshot = fCreateToolhelp32Snapshot(TiHelp32.TH32CS_SNAPTHREAD, 0);

            if (IntPtr.Zero == hSnapshot)
            {
                Misc.GetWin32Error("CreateToolhelp32Snapshot");
                CloseHandle(hKernel32);
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // Iterate through the first snapshot instance
            // kernel32.Thread32First(hSnapshot, ref threadEntry32);
            ////////////////////////////////////////////////////////////////////////////////

            TiHelp32.tagTHREADENTRY32 threadEntry32 = new TiHelp32.tagTHREADENTRY32()
            {
                dwSize = (uint)Marshal.SizeOf(typeof(TiHelp32.tagTHREADENTRY32))
            };

            IntPtr hThread32First = Generic.GetExportAddress(hKernel32, "Thread32First");
            MonkeyWorks.kernel32.Thread32First fThread32First = (MonkeyWorks.kernel32.Thread32First)Marshal.GetDelegateForFunctionPointer(hThread32First, typeof(MonkeyWorks.kernel32.Thread32First));
            if (!fThread32First(hSnapshot, ref threadEntry32))
            {
                Misc.GetWin32Error("Thread32First");
                return false;
            }

            if (threadEntry32.th32OwnerProcessID == processId)
            {
                threads.Add(threadEntry32.th32ThreadID);
            }

            ////////////////////////////////////////////////////////////////////////////////
            // Iterate through the remainder of the snapshot instances
            // kernel32.Thread32First(hSnapshot, ref threadEntry32);
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hThread32Next = Generic.GetExportAddress(hKernel32, "Thread32Next");
            MonkeyWorks.kernel32.Thread32Next fThread32Next = (MonkeyWorks.kernel32.Thread32Next)Marshal.GetDelegateForFunctionPointer(hThread32Next, typeof(MonkeyWorks.kernel32.Thread32Next));

            while (fThread32Next(hSnapshot, ref threadEntry32))
            {
                if (threadEntry32.th32OwnerProcessID == processId)
                {
                    threads.Add(threadEntry32.th32ThreadID);
                }
            }

            return true;
        }

        /// <summary>
        /// Opens a thread token
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="threadId"></param>
        /// <param name="permissions"></param>
        /// <returns></returns>
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public bool OpenThreadToken(uint threadId, uint permissions)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Open a limited handle to the thread via a syscall stub
            // IntPtr hThread = kernel32.OpenThread(ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION, false, threadId);
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hNtOpenThread = Generic.GetSyscallStub("NtOpenThread");
            MonkeyWorks.ntdll.NtOpenThread fSyscallNtOpenThread = (MonkeyWorks.ntdll.NtOpenThread)Marshal.GetDelegateForFunctionPointer(hNtOpenThread, typeof(MonkeyWorks.ntdll.NtOpenThread));

            IntPtr hThread = new IntPtr();
            MonkeyWorks.ntdll.OBJECT_ATTRIBUTES objectAttributes = new MonkeyWorks.ntdll.OBJECT_ATTRIBUTES();
            MonkeyWorks.ntdll.CLIENT_ID clientId = new MonkeyWorks.ntdll.CLIENT_ID();
            clientId.UniqueThread = new IntPtr(threadId);
           
            uint ntRetVal;
            try
            {
                //ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION
                ntRetVal = fSyscallNtOpenThread(ref hThread, ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION, ref objectAttributes, ref clientId);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtOpenThread Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtOpenThread", ntRetVal);
                return false;
            }
            //Console.WriteLine("[*] Recieved Thread Handle 0x{0}", hThread.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            // Open a handle to the thread token
            // bool retVal = kernel32.OpenThreadToken(hThread, permissions, false, ref hWorkingThreadToken);
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hNtOpenThreadToken = Generic.GetSyscallStub("NtOpenThreadToken");
            MonkeyWorks.ntdll.NtOpenThreadToken fSyscallNtOpenThreadToken = (MonkeyWorks.ntdll.NtOpenThreadToken)Marshal.GetDelegateForFunctionPointer(hNtOpenThreadToken, typeof(MonkeyWorks.ntdll.NtOpenThreadToken));

            try
            {
                ntRetVal = fSyscallNtOpenThreadToken(hThread, permissions, false, ref hWorkingThreadToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtOpenThreadToken Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                CloseHandle(hThread);
            }

            if (0 != ntRetVal)
            {
                //Skip error message if no token exists
                if (3221225596 != ntRetVal)
                {
                    Console.WriteLine(" [-] Unable to Open Process Token");
                    Misc.GetNtError("NtOpenProcessToken", ntRetVal);
                }
                return false;
            }

            Console.WriteLine("[*] Recieved Token Handle 0x{0}", hWorkingThreadToken.ToString("X4"));
            return true;
        }

        /// <summary>
        /// Creates a new process with the duplicated token
        /// No conversions required
        /// </summary>
        /// <param name="newProcess"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Impersonates the token from a specified processId
        /// Converted to D/Invoke Syscalls - still uses kernel32.GetCurrentThread()
        /// </summary>
        /// <returns></returns>
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public virtual bool ImpersonateUser()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Duplicate an existing token
            // Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            // advapi32.DuplicateTokenEx(hWorkingToken, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, ref securityAttributes, Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, Winnt._TOKEN_TYPE.TokenPrimary, out phNewToken)
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hNtDuplicateToken = Generic.GetSyscallStub("NtDuplicateToken");
            MonkeyWorks.ntdll.NtDuplicateToken fSyscallNtDuplicateToken = (MonkeyWorks.ntdll.NtDuplicateToken)Marshal.GetDelegateForFunctionPointer(hNtDuplicateToken, typeof(MonkeyWorks.ntdll.NtDuplicateToken));

            uint ntRetVal = 0;

            Winnt._SECURITY_QUALITY_OF_SERVICE securityContextTrackingMode = new Winnt._SECURITY_QUALITY_OF_SERVICE()
            {
                Length = (uint)Marshal.SizeOf(typeof(Winnt._SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,//SecurityAnonymous
                ContextTrackingMode = Winnt.SECURITY_CONTEXT_TRACKING_MODE.SECURITY_STATIC_TRACKING,
                EffectiveOnly = Winnt.EFFECTIVE_ONLY.False
            };

            IntPtr hSecurityContextTrackingMode = Marshal.AllocHGlobal(Marshal.SizeOf(securityContextTrackingMode));
            Marshal.StructureToPtr(securityContextTrackingMode, hSecurityContextTrackingMode, false);

            wudfwdm._OBJECT_ATTRIBUTES objectAttributes = new wudfwdm._OBJECT_ATTRIBUTES()
            {
                Length = (uint)Marshal.SizeOf(typeof(wudfwdm._OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                Attributes = 0,
                ObjectName = IntPtr.Zero,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = hSecurityContextTrackingMode
            };

            GCHandle hObjectAttributes = GCHandle.Alloc(objectAttributes, GCHandleType.Pinned);

            try
            {
                ntRetVal = fSyscallNtDuplicateToken(hWorkingToken, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, hObjectAttributes.AddrOfPinnedObject(), false, Winnt._TOKEN_TYPE.TokenImpersonation, ref phNewToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtDuplicateToken Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                hObjectAttributes.Free();
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtOpenProcessToken", ntRetVal);
                return false;
            }

            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            // Impersonate a newly duplicated token
            // advapi32.ImpersonateLoggedOnUser(phNewToken)            
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hNtSetInformationThread = Generic.GetSyscallStub("NtSetInformationThread");
            MonkeyWorks.ntdll.NtSetInformationThread fSyscallNtSetInformationThread = (MonkeyWorks.ntdll.NtSetInformationThread)Marshal.GetDelegateForFunctionPointer(hNtSetInformationThread, typeof(MonkeyWorks.ntdll.NtSetInformationThread));

            //If I get bored I can switch this over
            IntPtr hThread = kernel32.GetCurrentThread();

            try
            {
               ntRetVal = fSyscallNtSetInformationThread(hThread, MonkeyWorks.ntdll._THREAD_INFORMATION_CLASS.ThreadImpersonationToken, ref phNewToken, (uint)Marshal.SizeOf(phNewToken));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtSetInformationThread Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                CloseHandle(hThread);
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtSetInformationThread", ntRetVal);
                Console.ReadKey();
                return false;
            }

            Console.WriteLine("[+] Operating as {0}", WindowsIdentity.GetCurrent().Name);
            return true;
        }

        /// <summary>
        /// Closes an handle
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="handle"></param>
        /// <returns></returns>
        protected bool CloseHandle(IntPtr handle)
        {
            IntPtr hNtClose = Generic.GetSyscallStub("NtClose");
            MonkeyWorks.ntdll.NtClose fSyscallhNtClose = (MonkeyWorks.ntdll.NtClose)Marshal.GetDelegateForFunctionPointer(hNtClose, typeof(MonkeyWorks.ntdll.NtClose));
            uint ntRetVal = fSyscallhNtClose(handle);
            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtClose", ntRetVal);
                return false;
            }
            return true;
        }

        /// <summary>
        /// Default Deconstructor
        /// </summary>
        ~AccessTokens()
        {
            if (!Disposed)
            {
                Dispose();
            }
        }

        /// <summary>
        /// Closes all the opened handles
        /// Only Call D/Invoke Syscalls
        /// </summary>
        public void Dispose()
        {
            try
            {
                if (IntPtr.Zero != phNewToken)
                {                    
                    CloseHandle(phNewToken);
                }
                if (IntPtr.Zero != hExistingToken)
                {
                    CloseHandle(hExistingToken);
                }
                if (IntPtr.Zero != hWorkingToken && currentProcessToken != hWorkingToken)
                {
                    CloseHandle(hWorkingToken);
                }
                if (IntPtr.Zero != hWorkingThreadToken)
                {
                    CloseHandle(hWorkingThreadToken);
                }
            }
            catch (Exception ex)
            {
                if (!(ex is SEHException))
                {
                    Console.WriteLine(ex.Message);
                }
            }
            finally
            {
                Disposed = true;
            }
        }
    }
}
