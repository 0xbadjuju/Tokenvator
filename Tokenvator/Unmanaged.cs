using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Tokenvator
{
    class Unmanaged
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Processes
        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess, 
            Boolean bInheritHandle, 
            UInt32 dwProcessId
        );

        [DllImport("kernel32.dll")]
        public static extern Boolean OpenProcessToken(
            IntPtr hProcess,
            UInt32 dwDesiredAccess,
            out IntPtr hToken
        );

        ////////////////////////////////////////////////////////////////////////////////
        // Threads
        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();


        //Finish this
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(
            UInt32 dwDesiredAccess,
            Boolean bInheritHandle,
            UInt32 dwThreadId
        );

        [DllImport("kernel32.dll")]
        public static extern Boolean OpenThreadToken(
            IntPtr ThreadHandle,
            UInt32 DesiredAccess,
            Boolean OpenAsSelf,
            ref IntPtr TokenHandle
        );

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll")]
        public static extern Boolean CloseHandle(
            IntPtr hProcess
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean DuplicateTokenEx(
            IntPtr hExistingToken, 
            UInt32 dwDesiredAccess, 
            IntPtr lpTokenAttributes,
            Enums._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            Enums.TOKEN_TYPE TokenType, 
            out IntPtr phNewToken
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean ImpersonateLoggedOnUser(
            IntPtr hToken
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean ImpersonateSelf(
            Enums.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean CreateProcessAsUser(
            IntPtr hToken, 
            IntPtr lpApplicationName, 
            IntPtr lpCommandLine, 
            ref Structs._SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Structs._SECURITY_ATTRIBUTES lpThreadAttributes,
            Boolean bInheritHandles,
            Enums.CREATION_FLAGS dwCreationFlags, 
            IntPtr lpEnvironment, 
            IntPtr lpCurrentDirectory, 
            ref Structs._STARTUPINFO lpStartupInfo, 
            out Structs._PROCESS_INFORMATION lpProcessInfo
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean CreateProcessAsUserW(
            IntPtr hToken,
            IntPtr lpApplicationName,
            IntPtr lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            Boolean bInheritHandles,
            Enums.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            ref Structs._STARTUPINFO lpStartupInfo,
            out Structs._PROCESS_INFORMATION lpProcessInfo
        );

		[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
		public static extern bool CreateProcessWithLogonW(
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

        [DllImport("advapi32.dll")]
        public static extern Boolean CreateProcessWithTokenW(
            IntPtr hToken, 
            Enums.LOGON_FLAGS dwLogonFlags, 
            IntPtr lpApplicationName, 
            IntPtr lpCommandLine, 
            Enums.CREATION_FLAGS dwCreationFlags, 
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            ref Structs._STARTUPINFO lpStartupInfo,
            out Structs._PROCESS_INFORMATION lpProcessInfo
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean RevertToSelf();

        [DllImport("advapi32.dll")]
        public static extern Boolean AdjustTokenPrivileges(
            IntPtr TokenHandle,
            Boolean DisableAllPrivileges,
            ref Structs._TOKEN_PRIVILEGES NewState,
            UInt32 BufferLengthInBytes,
            ref Structs._TOKEN_PRIVILEGES PreviousState,
            out UInt32 ReturnLengthInBytes
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean LookupPrivilegeValue(
            String lpSystemName, 
            String lpName, 
            ref Structs._LUID luid
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean LookupPrivilegeName(
            String lpSystemName, 
            IntPtr lpLuid, 
            StringBuilder lpName, 
            ref Int32 cchName
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean GetTokenInformation(
            IntPtr TokenHandle, 
            Enums._TOKEN_INFORMATION_CLASS TokenInformationClass, 
            IntPtr TokenInformation, 
            UInt32 TokenInformationLength, 
            out UInt32 ReturnLength
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean AllocateAndInitializeSid(
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
        public static extern Int32 NtSetInformationToken(
            IntPtr TokenHandle,
            Int32 TokenInformationClass,
            ref Structs.TOKEN_MANDATORY_LABEL TokenInformation,
            Int32 TokenInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern int NtFilterToken(
            IntPtr TokenHandle,
            UInt32 Flags,
            IntPtr SidsToDisable,
            IntPtr PrivilegesToDelete,
            IntPtr RestrictedSids,
            ref IntPtr hToken
        );
    }
}
