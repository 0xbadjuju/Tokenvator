using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WheresMyImplant
{
    internal class Unmanaged
    {
        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32")]
        internal static extern IntPtr VirtualAlloc(IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern Boolean VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, ref UInt32 lpflOldProtect);

        [DllImport("kernel32")]
        internal static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32")]
        internal static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32")]
        internal static extern IntPtr VirtualAllocEx(IntPtr hHandle, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        internal static extern Boolean WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern Boolean VirtualProtectEx(IntPtr hHandle, IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, ref UInt32 lpflOldProtect);

        [DllImport("kernel32")]
        internal static extern IntPtr CreateRemoteThread(IntPtr hHandle, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32")]
        internal static extern UInt32 WaitForSingleObjectEx(IntPtr hProcess, IntPtr hHandle, UInt32 dwMilliseconds);

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern Boolean ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesRead);

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Tokens
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        internal static extern Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenThread(UInt32 dwDesiredAccess, Boolean bInheritHandle, UInt32 dwThreadId);

        [DllImport("kernel32.dll")]
        internal static extern Boolean OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, ref IntPtr TokenHandle);

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        internal static extern Boolean CloseHandle(IntPtr hProcess);

        [DllImport("advapi32.dll")]
        internal static extern Boolean DuplicateTokenEx(IntPtr hExistingToken, UInt32 dwDesiredAccess, IntPtr lpTokenAttributes, Enums._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, Enums.TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll")]
        internal static extern Boolean ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll")]
        internal static extern Boolean ImpersonateSelf(Enums.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

        [DllImport("advapi32.dll")]
        internal static extern Boolean RevertToSelf();

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("advapi32.dll")]
        internal static extern Boolean CreateProcessAsUser(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, ref Structs._SECURITY_ATTRIBUTES lpProcessAttributes, ref Structs._SECURITY_ATTRIBUTES lpThreadAttributes, Boolean bInheritHandles, Enums.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Structs._STARTUPINFO lpStartupInfo, out Structs._PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll")]
        internal static extern Boolean CreateProcessAsUserW(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, Boolean bInheritHandles, Enums.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Structs._STARTUPINFO lpStartupInfo, out Structs._PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll")]
        internal static extern Boolean CreateProcessWithTokenW(IntPtr hToken, Enums.LOGON_FLAGS dwLogonFlags, IntPtr lpApplicationName, IntPtr lpCommandLine, Enums.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Structs._STARTUPINFO lpStartupInfo, out Structs._PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            int logonFlags,
            String applicationName,
            String commandLine,
            int creationFlags,
            IntPtr environment,
            String currentDirectory,
            ref Structs._STARTUPINFO startupInfo,
            out Structs._PROCESS_INFORMATION processInformation
        );

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("advapi32.dll")]
        internal static extern Boolean AdjustTokenPrivileges(
            IntPtr TokenHandle, 
            Boolean DisableAllPrivileges, 
            ref Structs._TOKEN_PRIVILEGES NewState, 
            UInt32 BufferLengthInBytes, 
            ref Structs._TOKEN_PRIVILEGES PreviousState, 
            out UInt32 ReturnLengthInBytes
        );

        [DllImport("advapi32.dll")]
        internal static extern Boolean LookupPrivilegeValue(
            String lpSystemName, 
            String lpName, 
            ref Structs._LUID luid
        );

        [DllImport("advapi32.dll")]
        internal static extern Boolean LookupPrivilegeName(
            String lpSystemName, 
            IntPtr lpLuid, 
            StringBuilder lpName, 
            ref Int32 cchName
        );

        [DllImport("advapi32.dll")]
        internal static extern Boolean GetTokenInformation(
            IntPtr TokenHandle, 
            Enums._TOKEN_INFORMATION_CLASS TokenInformationClass, 
            IntPtr TokenInformation, 
            UInt32 TokenInformationLength, 
            out UInt32 ReturnLength
        );

        [DllImport("advapi32.dll")]
        internal static extern Boolean AllocateAndInitializeSid(
            ref Structs.SidIdentifierAuthority pIdentifierAuthority,
            byte nSubAuthorityCount,
            Int32 dwSubAuthority0,
            Int32 dwSubAuthority1,
            Int32 dwSubAuthority2,
            Int32 dwSubAuthority3,
            Int32 dwSubAuthority4,
            Int32 dwSubAuthority5,
            Int32 dwSubAuthority6,
            Int32 dwSubAuthority7,
            out IntPtr pSid
        );

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtSetInformationToken(
            IntPtr TokenHandle,
            Int32 TokenInformationClass,
            ref Structs.TOKEN_MANDATORY_LABEL TokenInformation,
            Int32 TokenInformationLength
        );

        [DllImport("ntdll.dll")]
        internal static extern int NtFilterToken(
            IntPtr TokenHandle,
            UInt32 Flags,
            IntPtr SidsToDisable,
            IntPtr PrivilegesToDelete,
            IntPtr RestrictedSids,
            ref IntPtr hToken
        );

        ////////////////////////////////////////////////////////////////////////////////
        internal const UInt32 PROCESS_CREATE_THREAD = 0x0002;
        internal const UInt32 PROCESS_QUERY_INFORMATION = 0x0400;
        internal const UInt32 PROCESS_VM_OPERATION = 0x0008;
        internal const UInt32 PROCESS_VM_WRITE = 0x0020;
        internal const UInt32 PROCESS_VM_READ = 0x0010;

        internal const UInt32 PROCESS_ALL_ACCESS = 0x1F0FFF;

        internal const UInt32 MEM_COMMIT = 0x00001000;
        internal const UInt32 MEM_RESERVE = 0x00002000;
    }
}