using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using Unmanaged.Headers;

namespace Unmanaged.Libraries
{
    class fltlib
    {
        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindFirst(
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            ref UInt32 lpBytesReturned,
            ref IntPtr lpFilterFind
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindNext(
            IntPtr hFilterFind,
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            out UInt32 lpBytesReturned
        );
    }
}
