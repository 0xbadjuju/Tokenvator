using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

using Tokenvator.Resources;

using DInvoke.DynamicInvoke;
using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.Execution
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    static class CreateProcess
    {
        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Wrapper for CreateProcessWithLogonW - for use token impersonation.
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="phNewToken"></param>
        /// <param name="name"></param>
        /// <param name="arguments"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public static bool CreateProcessWithLogonW(IntPtr phNewToken, string name, string arguments)
        {
            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            IntPtr hImpersonateLoggedOnUser = Generic.GetExportAddress(hadvapi32, "ImpersonateLoggedOnUser");
            var fImpersonateLoggedOnUser = (MonkeyWorks.advapi32.ImpersonateLoggedOnUser)Marshal.GetDelegateForFunctionPointer(hImpersonateLoggedOnUser, typeof(MonkeyWorks.advapi32.ImpersonateLoggedOnUser));

            IntPtr hRevertToSelf = Generic.GetExportAddress(hadvapi32, "RevertToSelf");
            var fRevertToSelf = (MonkeyWorks.advapi32.RevertToSelf)Marshal.GetDelegateForFunctionPointer(hRevertToSelf, typeof(MonkeyWorks.advapi32.RevertToSelf));

            IntPtr hCreateProcessWithLogonW = Generic.GetExportAddress(hadvapi32, "CreateProcessWithLogonW");
            var fCreateProcessWithLogonW = (MonkeyWorks.advapi32.CreateProcessWithLogonW)Marshal.GetDelegateForFunctionPointer(hCreateProcessWithLogonW, typeof(MonkeyWorks.advapi32.CreateProcessWithLogonW));
            
            if (name.Contains("\\"))
            {
                name = System.IO.Path.GetFullPath(name);
                if (!System.IO.File.Exists(name))
                {
                    Console.WriteLine("[-] File Not Found");
                    try
                    {
                        fRevertToSelf();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] RevertToSelf Generated an Exception");
                        Console.WriteLine("[-] {0}", ex.Message);
                    }
                    return false;
                }
            }
            else
            {
                name = FindFilePath(name);
                if (string.Empty == name)
                {
                    Console.WriteLine("[-] Unable to find file");
                    try
                    {
                        fRevertToSelf();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] RevertToSelf Generated an Exception");
                        Console.WriteLine("[-] {0}", ex.Message);
                    }
                    return false;
                }
            }

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.ImpersonateLoggedOnUser(phNewToken)
            ////////////////////////////////////////////////////////////////////////////////
            bool retVal = false;
            try
            {
                retVal = fImpersonateLoggedOnUser(phNewToken);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "ImpersonateLoggedOnUser");
                return false;
            }

            if (IntPtr.Zero != phNewToken && !retVal)
            {
                Misc.GetWin32Error("ImpersonateLoggedOnUser");
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.CreateProcessWithLogonW("i","j","k", Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY, name, name, Winbase.CREATION_FLAGS.CREATE_DEFAULT_ERROR_MODE, IntPtr.Zero, Environment.CurrentDirectory, ref startupInfo, out processInformation)
            ////////////////////////////////////////////////////////////////////////////////

            Console.WriteLine("[*] CreateProcessWithLogonW");
            Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO
            {
                cb = (uint)Marshal.SizeOf(typeof(Winbase._STARTUPINFO))
            };
            Winbase._PROCESS_INFORMATION processInformation;

            retVal = false;
            try
            {
                retVal = fCreateProcessWithLogonW(
                //OpSec warning, change these
                //This used to work with string.empty, another MS silent patch
                "tv", "tv", "tv",
                Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                name,
                name,
                Winbase.CREATION_FLAGS.CREATE_DEFAULT_ERROR_MODE,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out processInformation);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "CreateProcessWithLogonW");
                return false;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("CreateProcessWithLogonW");
                try
                {
                    fRevertToSelf();
                }
                catch (Exception ex)
                {
                    Misc.GetExceptionMessage(ex, "RevertToSelf");
                }

                return false;
            }
            
            Console.WriteLine(" [+] Created process: {0}", processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread:  {0}", processInformation.dwThreadId);

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.RevertToSelf();
            ////////////////////////////////////////////////////////////////////////////////
            try
            {
                fRevertToSelf();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] RevertToSelf Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Wrapper for CreateProcessWithLogonW - for use with explicit credentials
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="phNewToken"></param>
        /// <param name="name"></param>
        /// <param name="arguments"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public static bool CreateProcessWithLogonW(string username, string domain, string password, string command, string arguments)
        {
            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            IntPtr hCreateProcessWithLogonW = Generic.GetExportAddress(hadvapi32, "CreateProcessWithLogonW");
            MonkeyWorks.advapi32.CreateProcessWithLogonW fCreateProcessWithLogonW = (MonkeyWorks.advapi32.CreateProcessWithLogonW)Marshal.GetDelegateForFunctionPointer(hCreateProcessWithLogonW, typeof(MonkeyWorks.advapi32.CreateProcessWithLogonW));

            Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO
            {
                cb = (uint)Marshal.SizeOf(typeof(Winbase._STARTUPINFO))
            };
            Winbase._PROCESS_INFORMATION processInformation;

            bool retVal = false;
            try
            {
                retVal = fCreateProcessWithLogonW(
                    username, domain, password,
                    Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                    command,
                    arguments,
                    Winbase.CREATION_FLAGS.CREATE_NEW_PROCESS_GROUP,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    ref startupInfo,
                    out processInformation
                );
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "CreateProcessWithLogonW");
                return false;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("CreateProcessWithLogonW");
                return false;
            }

            Console.WriteLine("[+] Process ID: {0}", processInformation.dwProcessId);
            Console.WriteLine("[+] Thread ID:  {0}", processInformation.dwThreadId);

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Wrapper for CreateProcessWithTokenW
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="phNewToken"></param>
        /// <param name="name"></param>
        /// <param name="arguments"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public static bool CreateProcessWithTokenW(IntPtr phNewToken, string name, string arguments)
        {
            if (name.Contains(@"\"))
            {
                name = System.IO.Path.GetFullPath(name);
                if (!System.IO.File.Exists(name))
                {
                    Console.WriteLine("[-] File Not Found");
                    return false;
                }
            }
            else
            {
                name = FindFilePath(name);
                if (string.Empty == name)
                {
                    Console.WriteLine("[-] Unable to find file");
                    return false;
                }
            }

            ////////////////////////////////////////////////////////////////////////////////
            // !advapi32.CreateProcessWithTokenW(phNewToken, Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY, name, name + " " + arguments, Winbase.CREATION_FLAGS.NONE, IntPtr.Zero, Environment.CurrentDirectory, ref startupInfo, out processInformation)
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hCreateProcessWithTokenW = Generic.GetExportAddress(hadvapi32, "CreateProcessWithTokenW");
            MonkeyWorks.advapi32.CreateProcessWithTokenW fCreateProcessWithTokenW = (MonkeyWorks.advapi32.CreateProcessWithTokenW)Marshal.GetDelegateForFunctionPointer(hCreateProcessWithTokenW, typeof(MonkeyWorks.advapi32.CreateProcessWithTokenW));

            Console.WriteLine("[*] CreateProcessWithTokenW");
            Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO
            {
                cb = (uint)Marshal.SizeOf(typeof(Winbase._STARTUPINFO))
            };
            Winbase._PROCESS_INFORMATION processInformation;

            bool retVal = false;
            try
            {
                retVal = fCreateProcessWithTokenW(
                    phNewToken,
                    Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                    name,
                    name + " " + arguments,
                    Winbase.CREATION_FLAGS.NONE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    ref startupInfo,
                    out processInformation
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CreateProcessWithTokenW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
       
            if (!retVal)
            {
                if (267 == Marshal.GetLastWin32Error())
                {
                    Console.WriteLine(" [-] Function CreateProcessWithTokenW failed:");
                    Console.WriteLine(" [-] The directory name is invalid");
                    Console.WriteLine(" [*] User likely does not have permission in this directory");
                }
                else
                {
                    Misc.GetWin32Error("CreateProcessWithTokenW");
                }
                return false;
            }
            Console.WriteLine(" [+] Created process: {0}", processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread:  {0}", processInformation.dwThreadId);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// https://gist.github.com/tyranid/abad5008f5768b7718cd11d1a76a3763
        /// https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
        /// </summary>
        /// <param name="parent"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public static bool SpoofParentProcess(uint parent, out uint previousPid)
        {
            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");

            IntPtr hGetCurrentProcessId = Generic.GetExportAddress(hkernel32, "GetCurrentProcessId");
            var fGetCurrentProcessId = (MonkeyWorks.kernel32.GetCurrentProcessId)Marshal.GetDelegateForFunctionPointer(hGetCurrentProcessId, typeof(MonkeyWorks.kernel32.GetCurrentProcessId));

            IntPtr hNtQueryInformationThread = Generic.GetSyscallStub("NtQueryInformationThread");
            var fSyscallNtQueryInformationThread = (MonkeyWorks.ntdll.NtQueryInformationThread)Marshal.GetDelegateForFunctionPointer(hNtQueryInformationThread, typeof(MonkeyWorks.ntdll.NtQueryInformationThread));

            IntPtr hGetCurrentThread = Generic.GetExportAddress(hkernel32, "GetCurrentThread");
            var fGetCurrentThread = (MonkeyWorks.kernel32.GetCurrentThread)Marshal.GetDelegateForFunctionPointer(hGetCurrentThread, typeof(MonkeyWorks.kernel32.GetCurrentThread));

            previousPid = fGetCurrentProcessId();

            uint threadInformationLength = (uint)Marshal.SizeOf(typeof(MonkeyWorks.ntdll._THREAD_BASIC_INFORMATION));
            IntPtr threadInformation = Marshal.AllocHGlobal((int)threadInformationLength);

            MonkeyWorks.ntdll._THREAD_BASIC_INFORMATION threadBasicInformation;

            uint returnLength = 0;
            uint ntRetVal;
            try
            {
                ntRetVal = fSyscallNtQueryInformationThread(
                    fGetCurrentThread(), 
                    MonkeyWorks.ntdll._THREAD_INFORMATION_CLASS.ThreadBasicInformation, 
                    threadInformation, 
                    threadInformationLength, 
                    ref returnLength
                );
                threadBasicInformation = (MonkeyWorks.ntdll._THREAD_BASIC_INFORMATION)Marshal.PtrToStructure(threadInformation, typeof(MonkeyWorks.ntdll._THREAD_BASIC_INFORMATION));
                //Misc.PrintStruct(threadBasicInformation);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtQueryInformationThread");
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(threadInformation);
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtQueryInformationThread", ntRetVal);
                return false;
            }

            Console.WriteLine("[*] Modifying TEB");
            IntPtr hPid = new IntPtr(threadBasicInformation.TebBaseAddress.ToInt64() + 0x40);
            previousPid = (uint)Marshal.ReadInt32(hPid);
            Console.Write("[*] Current PID: {0}, ", previousPid);
            Marshal.WriteInt32(hPid, (int)parent);
            Console.WriteLine("Updated PID: {0}", parent);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Returns the full path to an executable specified by just its name
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public static string FindFilePath(string name)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // kernel32.SearchPath(null, name, null, (uint)lpFileName.Capacity, lpFileName, ref lpFilePart);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hSearchPathW = Generic.GetExportAddress(hkernel32, "SearchPathW");
            MonkeyWorks.kernel32.SearchPathW fSearchPathW = (MonkeyWorks.kernel32.SearchPathW)Marshal.GetDelegateForFunctionPointer(hSearchPathW, typeof(MonkeyWorks.kernel32.SearchPathW));

            StringBuilder lpFileName = new StringBuilder(260);
            IntPtr lpFilePart = new IntPtr();

            uint result = 0;
            try
            {
                result = fSearchPathW(null, name, null, (uint)lpFileName.Capacity, lpFileName, ref lpFilePart);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] RevertToSelf Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return string.Empty;
            }

            if (string.Empty == lpFileName.ToString())
            {
                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                return string.Empty;
            }
            return lpFileName.ToString();
        }
    }
}