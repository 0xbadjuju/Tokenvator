using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WheresMyImplant
{
    internal class kernel32
    {
        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        internal static extern Boolean CloseHandle(IntPtr hProcess);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        internal static extern void GetSystemInfo(out Winbase._SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32.dll")]
        internal static extern Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

        [DllImport("kernel32.dll")]
        internal static extern Boolean OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, ref IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        internal static extern Boolean ReadProcessMemory(IntPtr hProcess, UInt32 lpBaseAddress, IntPtr lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory")]
        internal static extern Boolean ReadProcessMemory64(IntPtr hProcess, UInt64 lpBaseAddress, IntPtr lpBuffer, UInt64 nSize, ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll", EntryPoint="VirtualQueryEx")]
        internal static extern Int32 VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out Winnt._MEMORY_BASIC_INFORMATION32 lpBuffer, UInt32 dwLength);

        [DllImport("kernel32.dll", EntryPoint="VirtualQueryEx")]
        internal static extern Int32 VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out Winnt._MEMORY_BASIC_INFORMATION64 lpBuffer, UInt32 dwLength);

    }
}