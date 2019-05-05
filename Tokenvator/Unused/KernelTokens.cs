using System;
using System.Runtime.InteropServices;

using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Libraries;

namespace Unused
{
    class KernelTokens
    {
        private delegate IntPtr PsGetCurrentProcess();

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _SYSTEM_MODULE_INFORMATION_ENTRY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public UIntPtr[] Reserved;
            public IntPtr ImageBase;
            public uint ImageSize;
            public uint Flags;
            public ushort LoadOrderIndex;
            public ushort InitOrderIndex;
            public ushort LoadCount;
            public ushort ModuleNameOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            internal char[] _ImageName;
            public string ImageName
            {
                get
                {
                    return new string(_ImageName).Split(new char[] { '\0' }, 2)[0];
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _SYSTEM_MODULE_INFORMATION
        {
            public uint Count;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public _SYSTEM_MODULE_INFORMATION_ENTRY[] Module;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);

        public KernelTokens()
        {

        }

        public void LoadKernalImage()
        {
            int returnLength = 0;

            uint status = NtQuerySystemInformation(11, IntPtr.Zero, 0, ref returnLength);
            if(0 != status && 3221225476 != status)
            {
                Misc.GetNtError("NtQuerySystemInformation1", status);
                return;
            }

            int bufferSize = returnLength;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            status = NtQuerySystemInformation(11, buffer, bufferSize, ref returnLength);
            if (0 != status)
            {
                Misc.GetNtError("NtQuerySystemInformation2", status);
                return;
            }

            var systemModuleInformation = (_SYSTEM_MODULE_INFORMATION)Marshal.PtrToStructure(buffer, typeof(_SYSTEM_MODULE_INFORMATION));
            

            IntPtr kernelBaseAddress = systemModuleInformation.Module[0].ImageBase;
            Console.WriteLine("Kernel Space Kernel Address: 0x{0}", kernelBaseAddress.ToString("X4"));

            IntPtr hKernelImage = kernel32.LoadLibrary("ntoskrnl.exe");
            if (IntPtr.Zero == hKernelImage)
            {
                Misc.GetWin32Error("LoadLibrary");
            }
            Console.WriteLine("User Space Kernel Address: 0x{0}", hKernelImage.ToString("X4"));

            /*
            IntPtr hPsGetCurrentProcess = kernel32.GetProcAddress(hKernelImage, "PsGetCurrentProcess");
            if (IntPtr.Zero == hPsGetCurrentProcess)
            {
                Misc.GetWin32Error("GetProcAddress: PsGetCurrentProcess");
            }
            Console.WriteLine("PsGetCurrentProcess Address: 0x{0}", hPsGetCurrentProcess.ToString("X4"));

            var psGetCurrentProcess = (PsGetCurrentProcess)Marshal.GetDelegateForFunctionPointer(hPsGetCurrentProcess, typeof(PsGetCurrentProcess));
            Console.WriteLine("Delegate: {0}", psGetCurrentProcess.Method);
            IntPtr pEPROCESS = psGetCurrentProcess();
            if(IntPtr.Zero == pEPROCESS)
            {
                Misc.GetWin32Error("psGetCurrentProcess");
            }
            Console.WriteLine("pEPROCESS Address: 0x{0}", pEPROCESS.ToString("X4"));

            Marshal.FreeHGlobal(buffer);
            */
        }
        
    }
}
