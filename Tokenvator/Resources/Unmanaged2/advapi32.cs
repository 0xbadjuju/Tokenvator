using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace WheresMyImplant
{
    class Advapi32
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Token Functions
        ////////////////////////////////////////////////////////////////////////////////

        ////////////////////////////////////////////////////////////////////////////////
        // Registry Functions
        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            UIntPtr hKey,
            String subKey,
            Int32 ulOptions,
            Int32 samDesired,
            out UIntPtr hkResult
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint RegQueryValueEx(
            UIntPtr hKey,
            String lpValueName,
            Int32 lpReserved,
            ref RegistryValueKind lpType,
            IntPtr lpData,
            ref Int32 lpcbData
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern UInt32 RegQueryValueEx(
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref Int32 lpType,
            IntPtr lpData,
            ref int lpcbData
        );

        [DllImport("advapi32.dll")]
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

        ////////////////////////////////////////////////////////////////////////////////
        // Vault Functions
        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("advapi32.dll")]
        public static extern Boolean CredEnumerateW(
            String Filter,
            Int32 Flags,
            out Int32 Count,
            out IntPtr Credentials
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean CredReadW(
            String target,
            Enums.CRED_TYPE type, 
            Int32 reservedFlag, 
            out IntPtr credentialPtr
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean CredWriteW(
            ref Structs._CREDENTIAL userCredential, 
            UInt32 flags
        );

        [DllImport("advapi32.dll")]
        public static extern Boolean CredFree(
            IntPtr Buffer
        );
    }
} 