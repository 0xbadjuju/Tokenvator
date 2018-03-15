using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

namespace WheresMyImplant
{
    public class Winbase
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct _SYSTEM_INFO 
        {
            public WORD wProcessorArchitecture;
            public WORD wReserved;
            public DWORD dwPageSize;
            public LPVOID lpMinimumApplicationAddress;
            public LPVOID lpMaximumApplicationAddress;
            public DWORD_PTR dwActiveProcessorMask;
            public DWORD dwNumberOfProcessors;
            public DWORD dwProcessorType;
            public DWORD dwAllocationGranularity;
            public WORD wProcessorLevel;
            public WORD wProcessorRevision;
        }
    }
}