using System;
using System.Runtime.InteropServices;

using Unmanaged.Headers;

namespace Unmanaged.Libraries
{
    class fileapi
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean ReadFile(
            IntPtr hFile,
            ref Byte[] lpBuffer,
            UInt32 nNumberOfBytesToRead,
            ref UInt32 lpNumberOfBytesRead,
            IntPtr lpOverlapped
            //MinWinBase._OVERLAPPED lpOverlapped
        );
    }
}
