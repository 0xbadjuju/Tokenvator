using System;
using System.Runtime.InteropServices;
using System.Text;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    class CreateProcess
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for ProcessWithLogonW
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean CreateProcessWithLogonW(IntPtr phNewToken, String name, String arguments)
        {
            if (name.Contains("\\"))
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
                if (String.Empty == name)
                {
                    Console.WriteLine("[-] Unable to find file");
                    return false;
                }
            }

            Console.WriteLine("[*] CreateProcessWithLogonW");
            Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Winbase._STARTUPINFO));
            Winbase._PROCESS_INFORMATION processInformation = new Winbase._PROCESS_INFORMATION();
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
                Tokens.GetWin32Error("CreateProcessWithLogonW");
                return false;
            }
            
            Console.WriteLine(" [+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread: " + processInformation.dwThreadId);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for CreateProcessWithTokenW
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean CreateProcessWithTokenW(IntPtr phNewToken, String name, String arguments)
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
                if (String.Empty == name)
                {
                    Console.WriteLine("[-] Unable to find file");
                    return false;
                }
            }
            
            Console.WriteLine("[*] CreateProcessWithTokenW");
            Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO
            {
                cb = (UInt32)Marshal.SizeOf(typeof(Winbase._STARTUPINFO))
            };
            Winbase._PROCESS_INFORMATION processInformation = new Winbase._PROCESS_INFORMATION();
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
                Tokens.GetWin32Error("CreateProcessWithTokenW");
                return false;
            }
            Console.WriteLine(" [+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread: " + processInformation.dwThreadId);
            return true;
        }

        public static String FindFilePath(String name)
        {
            StringBuilder lpFileName = new StringBuilder(260);
            IntPtr lpFilePart = new IntPtr();
            UInt32 result = kernel32.SearchPath(null, name, null, (UInt32)lpFileName.Capacity, lpFileName, ref lpFilePart);
            if (String.Empty == lpFileName.ToString())
            {
                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                return String.Empty;
            }
            return lpFileName.ToString();
        }
    }
}