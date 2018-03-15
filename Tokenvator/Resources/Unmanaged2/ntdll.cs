using System;
using System.Runtime.InteropServices;

namespace WheresMyImplant
{
    class ntdll
    {
        [DllImport("ntdll.dll")]
        internal static extern int NtFilterToken(
            IntPtr TokenHandle,
            UInt32 Flags,
            IntPtr SidsToDisable,
            IntPtr PrivilegesToDelete,
            IntPtr RestrictedSids,
            ref IntPtr hToken
        );

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtSetInformationToken(
            IntPtr TokenHandle,
            Int32 TokenInformationClass,
            ref Structs.TOKEN_MANDATORY_LABEL TokenInformation,
            Int32 TokenInformationLength
        );
    }
}