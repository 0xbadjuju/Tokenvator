using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    class FilterInstance : Filters
    {
        private String filterName;

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal FilterInstance(String filterName) : base()
        {
            this.filterName = filterName;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal override void First()
        {
            Console.WriteLine("{0,-20} {1,-11} {2,8} {3,-20}", "Instance Name", "Filter Name", "Altitude", "Volume Name");
            Console.WriteLine("{0,-20} {1,-11} {2,8} {3,-20}", "-------------", "-----------", "--------", "-----------");

            UInt32 dwBytesReturned = 0;
            UInt32 result = fltlib.FilterInstanceFindFirst(filterName, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);

            if (2149515283 == result)
            {
                Console.WriteLine("Filter Not Found");
                Dispose();
                return;
            }

            if (2147942522 != result || 0 == dwBytesReturned)
            {
                return;
            }

            IntPtr lpBuffer = Marshal.AllocHGlobal((int)dwBytesReturned);
            fltlib.FilterInstanceFindFirst(filterName, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, lpBuffer, dwBytesReturned, ref dwBytesReturned, ref hFilters);

            Print(lpBuffer);
            Marshal.FreeHGlobal(lpBuffer);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal override void Next()
        {
            if (IntPtr.Zero == hFilters)
            {
                return;
            }

            UInt32 lpBytesReturned = 0;
            UInt32 result = 0;
            do
            {
                if (2147942522 != fltlib.FilterInstanceFindNext(hFilters, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, IntPtr.Zero, 0, ref lpBytesReturned))
                {
                    break;
                }
                IntPtr lpBuffer = Marshal.AllocHGlobal((Int32)lpBytesReturned);
                result = fltlib.FilterInstanceFindNext(hFilters, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, lpBuffer, lpBytesReturned, ref lpBytesReturned);
                Print(lpBuffer);
                Marshal.FreeHGlobal(lpBuffer);
            }
            while (0 == result);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private void Print(IntPtr baseAddress)
        {
            var info = (FltUserStructures._INSTANCE_FULL_INFORMATION)Marshal.PtrToStructure(baseAddress, typeof(FltUserStructures._INSTANCE_FULL_INFORMATION));

            Int32 offset = 0;
            while (true)
            {
                IntPtr lpName = new IntPtr(baseAddress.ToInt64() + info.InstanceNameBufferOffset);
                String name = Marshal.PtrToStringUni(lpName, info.InstanceNameLength / 2);
                
                IntPtr lpFilter = new IntPtr(baseAddress.ToInt64() + info.FilterNameBufferOffset);
                String filter = Marshal.PtrToStringUni(lpFilter, info.FilterNameLength / 2);

                IntPtr lpAltitude = new IntPtr(baseAddress.ToInt64() + info.AltitudeBufferOffset);
                String altitude = Marshal.PtrToStringUni(lpAltitude, info.AltitudeLength / 2);

                IntPtr lpVolume = new IntPtr(baseAddress.ToInt64() + info.VolumeNameBufferOffset);
                String volume = Marshal.PtrToStringUni(lpVolume, info.VolumeNameLength / 2);
                
                Console.WriteLine("{0,-20} {1,-11} {2,8} {3,-20}", name, filter, altitude, volume);
                if (0 == info.NextEntryOffset)
                {
                    return;
                }
                IntPtr updatedBase = new IntPtr(baseAddress.ToInt64() + offset);
                info = (FltUserStructures._INSTANCE_FULL_INFORMATION)Marshal.PtrToStructure(updatedBase, typeof(FltUserStructures._INSTANCE_FULL_INFORMATION));
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        ~FilterInstance()
        {
            Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public override void Dispose()
        {
            fltlib.FilterInstanceFindClose(hFilters);
        }
    }
}
