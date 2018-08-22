using System;
using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using USHORT = System.UInt16;
using ULONG = System.UInt32;

using LPCTSTR = System.String;
using LPWSTR = System.Text.StringBuilder;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

using WCHAR = System.Char;

namespace Unmanaged.Headers
{
    public class FltUserStructures
    {
        public enum _FILTER_INFORMATION_CLASS
        {
            FilterFullInformation,
            FilterAggregateBasicInformation,
            FilterAggregateStandardInformation
        }
        //FILTER_INFORMATION_CLASS, *PFILTER_INFORMATION_CLASS;

        [StructLayout(LayoutKind.Sequential)]
        public struct _FILTER_AGGREGATE_BASIC_INFORMATION
        {
            public ULONG NextEntryOffset;
            public ULONG Flags;
            public ULONG FrameID;
            public ULONG NumberOfInstances;
            public USHORT FilterNameLength;
            public USHORT FilterNameBufferOffset;
            public USHORT FilterAltitudeLength;
            public USHORT FilterAltitudeBufferOffset;
        }
        //FILTER_AGGREGATE_BASIC_INFORMATION, *PFILTER_AGGREGATE_BASIC_INFORMATION;

        [StructLayout(LayoutKind.Sequential)]
        public struct _FILTER_AGGREGATE_STANDARD_INFORMATION
        {
            public ULONG NextEntryOffset;
            public ULONG Flags;
            public ULONG FrameID;
            public ULONG NumberOfInstances;
            public USHORT FilterNameLength;
            public USHORT FilterNameBufferOffset;
            public USHORT FilterAltitudeLength;
            public USHORT FilterAltitudeBufferOffset;
        }
        // FILTER_AGGREGATE_STANDARD_INFORMATION, * PFILTER_AGGREGATE_STANDARD_INFORMATION;

        [StructLayout(LayoutKind.Sequential)]
        public struct _FILTER_FULL_INFORMATION
        {
            public ULONG NextEntryOffset;
            public ULONG FrameID;
            public ULONG NumberOfInstances;
            public USHORT FilterNameLength;
            public WCHAR[] FilterNameBuffer;
        }
        //FILTER_FULL_INFORMATION, *PFILTER_FULL_INFORMATION;
    }
}
