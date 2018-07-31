using System;
using System.Runtime.InteropServices;

using Unmanaged.Headers;

namespace Unmanaged.Libraries
{
    sealed class ntdll
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtCreateProcessEx(
            ref IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr hInheritFromProcess,
            UInt32 Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            Byte InJob
        );

        [DllImport("ntdll.dll", SetLastError = true)]
		public static extern UInt32 NtCreateThreadEx(
			ref IntPtr hThread,
			UInt32 DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ProcessHandle,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
			Boolean CreateSuspended,
			UInt32 StackZeroBits,
			UInt32 SizeOfStackCommit,
			UInt32 SizeOfStackReserve,
			IntPtr lpBytesBuffer
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtFilterToken(
            IntPtr TokenHandle,
            UInt32 Flags,
            IntPtr SidsToDisable,
            IntPtr PrivilegesToDelete,
            IntPtr RestrictedSids,
            ref IntPtr hToken
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtGetContextThread(
            IntPtr ProcessHandle,
            IntPtr lpContext
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            UInt32 ProcessInformationLength,
            ref UInt32 ReturnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtSetInformationToken(
            IntPtr TokenHandle,
            Int32 TokenInformationClass,
            ref Winnt._TOKEN_MANDATORY_LABEL TokenInformation,
            Int32 TokenInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtUnmapViewOfSection(
            IntPtr hProcess,
            IntPtr baseAddress
        );

        [Flags]
        public enum PROCESSINFOCLASS
        {
            ProcessBasicInformation = 0,
            ProcessDebugPort = 7,
            ProcessWow64Information = 26,
            ProcessImageFileName = 27,
            ProcessBreakOnTermination = 29,
            ProcessSubsystemInformation = 75
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

    }
}