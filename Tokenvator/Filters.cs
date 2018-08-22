using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

using Unmanaged.Headers;
using Unmanaged.Libraries;

namespace Tokenvator
{
    class Filters
    {
        private Int32 count;
        private IntPtr hFilters;

        private FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION info;

        internal Filters()
        {
            Console.WriteLine();
            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "Frame ID", "Instances", "Altitude", "Name");
            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "--------", "---------", "--------", "----");
        }

        internal void First()
        {
            UInt32 dwBytesReturned = 0;
            UInt32 result = fltlib.FilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);

            if (2147942522 != result || 0 == dwBytesReturned)
            {
                return;
            }
            IntPtr lpBuffer = Marshal.AllocHGlobal((int)dwBytesReturned);            
            fltlib.FilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, lpBuffer, dwBytesReturned, ref dwBytesReturned, ref hFilters);
            
            Print(lpBuffer);
            Marshal.FreeHGlobal(lpBuffer);
        }

        internal void Next()
        {
            UInt32 result = 0;
            do
            {
                if (2147942522 != fltlib.FilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, out UInt32 lpBytesReturned))
                {
                    break;
                }
                IntPtr lpBuffer = Marshal.AllocHGlobal((Int32)lpBytesReturned);
                result = fltlib.FilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, lpBuffer, lpBytesReturned, out lpBytesReturned);
                                
                Print(lpBuffer);
                Marshal.FreeHGlobal(lpBuffer);
            }
            while (0 == result);
        }

        private static void Print(IntPtr baseAddress)
        {
            FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION info = (FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION)Marshal.PtrToStructure(baseAddress, typeof(FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION));

            UInt32 offset = 0;
            do
            {
                IntPtr lpAltitude = new IntPtr(baseAddress.ToInt64() + info.FilterAltitudeBufferOffset);
                String altitude = Marshal.PtrToStringUni(lpAltitude, info.FilterAltitudeLength / 2);

                IntPtr lpName = new IntPtr(baseAddress.ToInt64() + info.FilterNameBufferOffset);
                String name = Marshal.PtrToStringUni(lpName, info.FilterNameLength / 2);

                Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", info.FrameID, info.NumberOfInstances, altitude, name);

                offset = info.NextEntryOffset;
                info = (FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION)Marshal.PtrToStructure(new IntPtr(baseAddress.ToInt64() + offset), typeof(FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION));
            }
            while (0 != offset);
        }
    }
}
