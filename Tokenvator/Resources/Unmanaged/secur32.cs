using System;
using System.Runtime.InteropServices;

namespace Tokenvator
{
    class secur32
    {
        [DllImport("secur32.dll")]
        internal static extern UInt32 LsaGetLogonSessionData(
            IntPtr LogonId,
            out IntPtr ppLogonSessionData
        );
    }
}