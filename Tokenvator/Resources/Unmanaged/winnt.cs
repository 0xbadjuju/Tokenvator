using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;
using ULONGLONG = System.UInt64;
using LARGE_INTEGER = System.UInt64;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;

namespace Tokenvator
{
    public class Winnt
    {
        ////////////////////////////////////////////////////////////////////////////////
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
        ////////////////////////////////////////////////////////////////////////////////
        public const DWORD PAGE_NOACCESS = 0x01;
        public const DWORD PAGE_READONLY = 0x02;
        public const DWORD PAGE_READWRITE = 0x04;
        public const DWORD PAGE_WRITECOPY = 0x08;
        public const DWORD PAGE_EXECUTE = 0x10;
        public const DWORD PAGE_EXECUTE_READ = 0x20;
        public const DWORD PAGE_EXECUTE_READWRITE = 0x40;
        public const DWORD PAGE_EXECUTE_WRITECOPY = 0x80;
        public const DWORD PAGE_GUARD = 0x100;
        public const DWORD PAGE_NOCACHE = 0x200;
        public const DWORD PAGE_WRITECOMBINE = 0x400;
        public const DWORD PAGE_TARGETS_INVALID = 0x40000000;
        public const DWORD PAGE_TARGETS_NO_UPDATE = 0x40000000;

        internal enum _SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        internal enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct _MEMORY_BASIC_INFORMATION32
        {
            public DWORD BaseAddress;
            public DWORD AllocationBase;
            public DWORD AllocationProtect;
            public DWORD RegionSize;
            public DWORD State;
            public DWORD Protect;
            public DWORD Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct _MEMORY_BASIC_INFORMATION64
        {
            public ULONGLONG BaseAddress;
            public ULONGLONG AllocationBase;
            public DWORD AllocationProtect;
            public DWORD __alignment1;
            public ULONGLONG RegionSize;
            public DWORD State;
            public DWORD Protect;
            public DWORD Type;
            public DWORD __alignment2;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct _TOKEN_STATISTICS
        {
            public Structs._LUID TokenId;
            public Structs._LUID AuthenticationId;
            public LARGE_INTEGER ExpirationTime;
            public TOKEN_TYPE TokenType;
            public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
            public DWORD DynamicCharged;
            public DWORD DynamicAvailable;
            public DWORD GroupCount;
            public DWORD PrivilegeCount;
            public Structs._LUID ModifiedId;
        }
    }
}