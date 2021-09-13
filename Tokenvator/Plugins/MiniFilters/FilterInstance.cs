using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;

using DInvoke.DynamicInvoke;

using MonkeyWorks.Unmanaged.Headers;

using Tokenvator.Resources;

namespace Tokenvator.Plugins.MiniFilters
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    class FilterInstance : Filters
    {
        private bool disposed = false;

        private readonly string filterName;

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// 
        /// </summary>
        /// <param name="filterName"></param>
        ////////////////////////////////////////////////////////////////////////////////
        internal FilterInstance(string filterName) : base()
        {
            this.filterName = filterName;

        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// 
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal override bool First()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // First call to function to get buffer size
            // fltlib.FilterInstanceFindFirst(filterName, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterInstanceFindFirst = Generic.GetExportAddress(hfltlib, "FilterInstanceFindFirst");
            MonkeyWorks.fltlib.FilterInstanceFindFirst fFilterInstanceFindFirst = (MonkeyWorks.fltlib.FilterInstanceFindFirst)Marshal.GetDelegateForFunctionPointer(hFilterInstanceFindFirst, typeof(MonkeyWorks.fltlib.FilterInstanceFindFirst));

            uint dwBytesReturned = 0;
            uint retVal = 0;
            try
            {
                retVal = fFilterInstanceFindFirst(filterName, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterInstanceFindFirst Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
           
            if (ERROR_FLT_FILTER_NOT_FOUND == retVal)
            {
                Console.WriteLine("Filter Not Found");
                return false;
            }

            //Buffer too small is expected result
            if (ERROR_INSUFFICIENT_BUFFER != retVal || 0 == dwBytesReturned)
            {
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // fltlib.FilterInstanceFindFirst(filterName, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr lpBuffer = Marshal.AllocHGlobal((int)dwBytesReturned);

            try
            {
                retVal = fFilterInstanceFindFirst(filterName, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, lpBuffer, dwBytesReturned, ref dwBytesReturned, ref hFilters);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterInstanceFindFirst Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != retVal)
            {
                Misc.GetWin32Error("FilterInstanceFindFirst");
                return false;
            }

            Console.WriteLine("{0,-20} {1,-11} {2,8} {3,-20}", "Instance Name", "Filter Name", "Altitude", "Volume Name");
            Console.WriteLine("{0,-20} {1,-11} {2,8} {3,-20}", "-------------", "-----------", "--------", "-----------");

            Print(lpBuffer);
            Marshal.FreeHGlobal(lpBuffer);

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal override bool Next()
        {
            if (IntPtr.Zero == hFilters)
            {
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // First call to function to get buffer size
            // fltlib.FilterInstanceFindNext(hFilters, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, IntPtr.Zero, 0, ref lpBytesReturned)
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterInstanceFindNext = Generic.GetExportAddress(hfltlib, "FilterInstanceFindNext");
            MonkeyWorks.fltlib.FilterInstanceFindNext fFilterInstanceFindNext = (MonkeyWorks.fltlib.FilterInstanceFindNext)Marshal.GetDelegateForFunctionPointer(hFilterInstanceFindNext, typeof(MonkeyWorks.fltlib.FilterInstanceFindNext));

            uint lpBytesReturned = 0;
            uint retVal = 0;
            do
            {
                try
                {
                    retVal = fFilterInstanceFindNext(hFilters, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, IntPtr.Zero, 0, ref lpBytesReturned);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] FilterInstanceFindNext Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    return false;
                }

                if (ERROR_FLT_FILTER_NOT_FOUND == retVal)
                {
                    Console.WriteLine("Filter Not Found");
                    return false;
                }

                //Buffer too small is expected result
                if (ERROR_INSUFFICIENT_BUFFER != retVal || 0 == lpBytesReturned)
                {
                    break;
                }

                ////////////////////////////////////////////////////////////////////////////////
                // result = fltlib.FilterInstanceFindNext(hFilters, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, lpBuffer, lpBytesReturned, ref lpBytesReturned);
                ////////////////////////////////////////////////////////////////////////////////
                IntPtr lpBuffer = Marshal.AllocHGlobal((int)lpBytesReturned);

                try
                {
                    retVal = fFilterInstanceFindNext(hFilters, FltUserStructures._INSTANCE_INFORMATION_CLASS.InstanceFullInformation, lpBuffer, lpBytesReturned, ref lpBytesReturned);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] FilterInstanceFindNext Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    return false;
                }

                if (0 == retVal)
                {
                    Print(lpBuffer);
                    Marshal.FreeHGlobal(lpBuffer);
                }
            }
            while (0 == retVal);

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// 
        /// </summary>
        /// <param name="baseAddress"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private void Print(IntPtr baseAddress)
        {
            var info = (FltUserStructures._INSTANCE_FULL_INFORMATION)Marshal.PtrToStructure(baseAddress, typeof(FltUserStructures._INSTANCE_FULL_INFORMATION));

            int offset = 0;
            while (true)
            {
                IntPtr lpName = new IntPtr(baseAddress.ToInt64() + info.InstanceNameBufferOffset);
                string name = Marshal.PtrToStringUni(lpName, info.InstanceNameLength / 2);
                
                IntPtr lpFilter = new IntPtr(baseAddress.ToInt64() + info.FilterNameBufferOffset);
                string filter = Marshal.PtrToStringUni(lpFilter, info.FilterNameLength / 2);

                IntPtr lpAltitude = new IntPtr(baseAddress.ToInt64() + info.AltitudeBufferOffset);
                string altitude = Marshal.PtrToStringUni(lpAltitude, info.AltitudeLength / 2);

                IntPtr lpVolume = new IntPtr(baseAddress.ToInt64() + info.VolumeNameBufferOffset);
                string volume = Marshal.PtrToStringUni(lpVolume, info.VolumeNameLength / 2);
                
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
        /// <summary>
        /// 
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        ~FilterInstance()
        {
            if (!disposed)
            {
                Dispose();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// 
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public override void Dispose()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Closes the filter instance handle
            // fltlib.FilterInstanceFindClose(hFilters);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterInstanceFindClose = Generic.GetExportAddress(hfltlib, "FilterInstanceFindClose");
            MonkeyWorks.fltlib.FilterInstanceFindClose fFilterInstanceFindClose = (MonkeyWorks.fltlib.FilterInstanceFindClose)Marshal.GetDelegateForFunctionPointer(hFilterInstanceFindClose, typeof(MonkeyWorks.fltlib.FilterInstanceFindClose));

            uint retVal = 0;
            try
            {
                retVal = fFilterInstanceFindClose(hFilters);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterInstanceFindClose Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }
            finally
            {
                disposed = true;
            }
        }
    }
}
