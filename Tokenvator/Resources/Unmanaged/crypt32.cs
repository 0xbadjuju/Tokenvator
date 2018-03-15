using System;
using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using LPWSTR = System.Text.StringBuilder;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

namespace Tokenvator
{
    class crypt32
    {
        [DllImport("crypt32.dll", SetLastError=true)]
        internal static extern bool CryptUnprotectData(
            ref Wincrypt._CRYPTOAPI_BLOB pDataIn,
            LPWSTR ppszDataDescr,
            ref Wincrypt._CRYPTOAPI_BLOB pOptionalEntropy,
            PVOID pvReserved,
            ref Wincrypt._CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            DWORD dwFlag,
            ref Wincrypt._CRYPTOAPI_BLOB pDataOut
        );
    }
}