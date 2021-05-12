using System;
using System.Runtime.InteropServices;
using System.Text;

using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.Execution
{
    static class CreateProcess
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for ProcessWithLogonW
        ////////////////////////////////////////////////////////////////////////////////
        public static bool CreateProcessWithLogonW(IntPtr phNewToken, string name, string arguments)
        {
            if (IntPtr.Zero != phNewToken && !advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                Console.WriteLine("[-] Token Impersonation Failed");
                Misc.GetWin32Error("ImpersonateLoggedOnUser");
                return false;
            }

            if (name.Contains("\\"))
            {
                name = System.IO.Path.GetFullPath(name);
                if (!System.IO.File.Exists(name))
                {
                    Console.WriteLine("[-] File Not Found");
                    advapi32.RevertToSelf();
                    return false;
                }
            }
            else
            {
                name = FindFilePath(name);
                if (string.Empty == name)
                {
                    Console.WriteLine("[-] Unable to find file");
                    advapi32.RevertToSelf();
                    return false;
                }
            }

            Console.WriteLine("[*] CreateProcessWithLogonW");
            Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO
            {
                cb = (uint)Marshal.SizeOf(typeof(Winbase._STARTUPINFO))
            };
            Winbase._PROCESS_INFORMATION processInformation;
            if (!advapi32.CreateProcessWithLogonW("i","j","k",
                Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                name,
                name,
                Winbase.CREATION_FLAGS.CREATE_DEFAULT_ERROR_MODE,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out processInformation
            ))
            {
                Misc.GetWin32Error("CreateProcessWithLogonW");
                advapi32.RevertToSelf();
                return false;
            }
            
            Console.WriteLine(" [+] Created process: {0}", processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread:  {0}", processInformation.dwThreadId);
            advapi32.RevertToSelf();
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for CreateProcessWithTokenW
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
            
            Console.WriteLine("[*] CreateProcessWithTokenW");
            Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO
            {
                cb = (uint)Marshal.SizeOf(typeof(Winbase._STARTUPINFO))
            };
            Winbase._PROCESS_INFORMATION processInformation;
            if (!advapi32.CreateProcessWithTokenW(
                phNewToken,
                Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                name,
                name + " " + arguments,
                Winbase.CREATION_FLAGS.NONE,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out processInformation
            ))
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static string FindFilePath(string name)
        {
            StringBuilder lpFileName = new StringBuilder(260);
            IntPtr lpFilePart = new IntPtr();
            uint result = kernel32.SearchPath(null, name, null, (uint)lpFileName.Capacity, lpFileName, ref lpFilePart);
            if (string.Empty == lpFileName.ToString())
            {
                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                return string.Empty;
            }
            return lpFileName.ToString();
        }
    }
}