using System;
using System.Runtime.InteropServices;

namespace Tokenvator
{
    class CreateProcess
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for ProcessWithLogonW
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean CreateProcessWithLogonW(IntPtr phNewToken, String name, String arguments)
        {
            Console.WriteLine("[*] CreateProcessWithLogonW");
            IntPtr lpProcessName = Marshal.StringToHGlobalUni(name);
            IntPtr lpProcessArgs = Marshal.StringToHGlobalUni(name);
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
                "C:\\Windows\\System32",
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
            Console.WriteLine("[*] CreateProcessWithTokenW");
            IntPtr lpProcessName = Marshal.StringToHGlobalUni(name);
            IntPtr lpProcessArgs = Marshal.StringToHGlobalUni(name);
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
    }
}