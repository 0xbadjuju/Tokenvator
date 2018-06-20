using System;
using System.Runtime.InteropServices;
using System.Text;

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
            Structs._STARTUPINFO startupInfo = new Structs._STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Structs._STARTUPINFO));
            Structs._PROCESS_INFORMATION processInformation = new Structs._PROCESS_INFORMATION();
            if (!advapi32.CreateProcessWithLogonW(
                "i",
                "j",
                "k",
                0x00000002,
                name,
                arguments,
                0x04000000,
                IntPtr.Zero,
                Environment.SystemDirectory,
                ref startupInfo,
                out processInformation
            ))
            {
                Console.WriteLine(" [-] Function CreateProcessWithLogonW failed: " + Marshal.GetLastWin32Error());
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
            
            Console.WriteLine("[*] CreateProcessWithTokenW");
            IntPtr lpProcessName = Marshal.StringToHGlobalUni(name);
            IntPtr lpProcessArgs = Marshal.StringToHGlobalUni(arguments);
            Structs._STARTUPINFO startupInfo = new Structs._STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Structs._STARTUPINFO));
            Structs._PROCESS_INFORMATION processInformation = new Structs._PROCESS_INFORMATION();
            if (!advapi32.CreateProcessWithTokenW(
                phNewToken,
                Enums.LOGON_FLAGS.NetCredentialsOnly,
                lpProcessName,
                lpProcessArgs,
                Enums.CREATION_FLAGS.NONE,
                IntPtr.Zero,
                IntPtr.Zero,
                ref startupInfo,
                out processInformation
            ))
            {
                Console.WriteLine(" [-] Function CreateProcessWithTokenW failed: " + Marshal.GetLastWin32Error());
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