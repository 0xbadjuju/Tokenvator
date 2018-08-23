using System;
using System.Runtime.InteropServices;

using Unmanaged.Headers;
using Unmanaged.Libraries;

namespace Tokenvator
{
    class Filters : IDisposable
    {
        protected IntPtr hFilters;
        private FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION info;

        internal Filters()
        {
            Console.WriteLine();
        }

        internal virtual void First()
        {
            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "Frame ID", "Instances", "Altitude", "Filter Name");
            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "--------", "---------", "--------", "-----------");

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

        internal virtual void Next()
        {
            if (IntPtr.Zero == hFilters)
            {
                return;
            }

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
            var info = (FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION)Marshal.PtrToStructure(baseAddress, typeof(FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION));

            UInt32 offset = 0;
            do
            {
                IntPtr lpAltitude = new IntPtr(baseAddress.ToInt64() + info.FilterAltitudeBufferOffset);
                String altitude = Marshal.PtrToStringUni(lpAltitude, info.FilterAltitudeLength / 2);

                String alarm = "";
                if (UInt32.TryParse(altitude, out UInt32 dwAltitude))
                {
                    if (320000 <= dwAltitude && 329998 >= dwAltitude)
                    {
                        alarm = "[!] Anti-Virus";
                    }

                    else if (140000 <= dwAltitude && 149999 >= dwAltitude)
                    {
                        alarm = "[*] Encryption";
                    }

                    else if (80000 <= dwAltitude && 89999 >= dwAltitude)
                    {
                        alarm = "[!] Security Enhancer";

                    }
                }

                IntPtr lpName = new IntPtr(baseAddress.ToInt64() + info.FilterNameBufferOffset);
                String name = Marshal.PtrToStringUni(lpName, info.FilterNameLength / 2);

                Console.WriteLine("{0,8} {1,9} {2,8} {3,-20} {4,-15}", info.FrameID, info.NumberOfInstances, altitude, name, alarm);

                IntPtr updatedBase = new IntPtr(baseAddress.ToInt64() + info.NextEntryOffset);
                info = (FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION)Marshal.PtrToStructure(updatedBase, typeof(FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION));
            }
            while (0 != offset);
        }

        internal static void FilterDetach(String filterName, String volumeName)
        {
            fltlib.FilterDetach(filterName, volumeName, String.Empty);
        }

        internal static void Unload(String filterName)
        {
            fltlib.FilterUnload(filterName);
        }

        ~Filters()
        {
            Dispose();
        }

        public virtual void Dispose()
        {
            fltlib.FilterFindClose(hFilters);
        }
    }
}
