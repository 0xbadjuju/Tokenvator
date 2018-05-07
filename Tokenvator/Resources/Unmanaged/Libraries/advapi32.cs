using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace Tokenvator
{
    class advapi32
    {
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean AdjustTokenPrivileges(
            IntPtr TokenHandle,
            Boolean DisableAllPrivileges,
            ref Structs._TOKEN_PRIVILEGES NewState,
            UInt32 BufferLengthInBytes,
            ref Structs._TOKEN_PRIVILEGES PreviousState,
            out UInt32 ReturnLengthInBytes
        );

        [DllImport("advapi32.dll", SetLastError=true)]
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

        [DllImport("advapi32.dll", SetLastError = true)]
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
            ref Structs._SID pSid
        );

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(
            IntPtr pSID,
            out IntPtr ptrSid
        );

        [DllImport("advapi32.dll", SetLastError=true)]
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

        [DllImport("advapi32.dll", SetLastError=true)]
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

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
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

        [DllImport("advapi32.dll", SetLastError=true)]
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

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean CredEnumerateW(
            String Filter,
            Int32 Flags,
            out Int32 Count,
            out IntPtr Credentials
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean CredFree(
            IntPtr Buffer
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean CredReadW(
            String target,
            Enums.CRED_TYPE type,
            Int32 reservedFlag,
            out IntPtr credentialPtr
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean CredWriteW(
            ref Structs._CREDENTIAL userCredential,
            UInt32 flags
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean DuplicateTokenEx(
            IntPtr hExistingToken,
            UInt32 dwDesiredAccess,
            ref Structs._SECURITY_ATTRIBUTES lpTokenAttributes,
            Enums._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            Enums.TOKEN_TYPE TokenType,
            out IntPtr phNewToken
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean GetTokenInformation(
            IntPtr TokenHandle,
            Enums._TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            UInt32 TokenInformationLength,
            out UInt32 ReturnLength
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean GetTokenInformation(
            IntPtr TokenHandle,
            Enums._TOKEN_INFORMATION_CLASS TokenInformationClass,
            ref Winnt._TOKEN_STATISTICS TokenInformation,
            UInt32 TokenInformationLength,
            out UInt32 ReturnLength
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean ImpersonateLoggedOnUser(
            IntPtr hToken
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean ImpersonateSelf(
            Enums.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
        );

        [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Auto)]
        public static extern bool LookupAccountSid(
            String lpSystemName,
            //[MarshalAs(UnmanagedType.LPArray)] 
            IntPtr Sid,
            StringBuilder lpName,
            ref UInt32 cchName,
            StringBuilder ReferencedDomainName,
            ref UInt32 cchReferencedDomainName,
            out Enums._SID_NAME_USE peUse
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean LookupPrivilegeName(
            String lpSystemName,
            IntPtr lpLuid,
            StringBuilder lpName,
            ref Int32 cchName
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean LookupPrivilegeValue(
            String lpSystemName,
            String lpName,
            ref Structs._LUID luid
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean PrivilegeCheck(
            IntPtr ClientToken,
            Structs._PRIVILEGE_SET RequiredPrivileges,
            out IntPtr pfResult
        );
        
        [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            UIntPtr hKey,
            String subKey,
            Int32 ulOptions,
            Int32 samDesired,
            out UIntPtr hkResult
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern uint RegQueryValueEx(
            UIntPtr hKey,
            String lpValueName,
            Int32 lpReserved,
            ref RegistryValueKind lpType,
            IntPtr lpData,
            ref Int32 lpcbData
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Int32 RegQueryInfoKey(
            UIntPtr hKey,
            StringBuilder lpClass,
            ref UInt32 lpcchClass,
            IntPtr lpReserved,
            out UInt32 lpcSubkey,
            out UInt32 lpcchMaxSubkeyLen,
            out UInt32 lpcchMaxClassLen,
            out UInt32 lpcValues,
            out UInt32 lpcchMaxValueNameLen,
            out UInt32 lpcbMaxValueLen,
            IntPtr lpSecurityDescriptor,
            IntPtr lpftLastWriteTime
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern Boolean RevertToSelf();
    }
} 