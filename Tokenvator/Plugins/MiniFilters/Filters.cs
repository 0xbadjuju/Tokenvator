using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using DInvoke.DynamicInvoke;

using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

using Tokenvator.Resources;

namespace Tokenvator.Plugins.MiniFilters
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    class Filters : IDisposable
    {
        private bool disposed = false;

        protected const uint ERROR_FLT_FILTER_NOT_FOUND = 2149515283;
        protected const uint ERROR_INSUFFICIENT_BUFFER = 2147942522;
        protected const uint ERROR_PRIVILEGE_NOT_HELD = 2147943714;
        protected const uint ERROR_FLT_DO_NOT_DETACH = 2149515280;

        protected IntPtr hfltlib;

        protected IntPtr hFilters = IntPtr.Zero;
        //private FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION info;

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default constructor
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public Filters()
        {
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Loads the fltlib.dll for invocation
        /// Converted to D/Invoke GetPebLdrModuleEntry/LoadModuleFromDisk
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        internal bool Load()
        {
            hfltlib = Generic.GetPebLdrModuleEntry("fltlib.dll");
            if (IntPtr.Zero == hfltlib)
            {
                hfltlib = Generic.LoadModuleFromDisk("fltlib.dll");
                if (IntPtr.Zero == hfltlib)
                {
                    Console.WriteLine("Unable to load fltlib.dll");

                    disposed = true;

                    return false;
                }
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Iterates through the first filter returned by the handle
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal virtual bool First()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // First call to function to get buffer size
            // fltlib.FilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterFindFirst = Generic.GetExportAddress(hfltlib, "FilterFindFirst");
            MonkeyWorks.fltlib.FilterFindFirst fFilterFindFirst = (MonkeyWorks.fltlib.FilterFindFirst)Marshal.GetDelegateForFunctionPointer(hFilterFindFirst, typeof(MonkeyWorks.fltlib.FilterFindFirst));

            uint dwBytesReturned = 0;
            uint retVal = 0;
            try
            {
                retVal = fFilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterFindFirst Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            //Buffer too small is expected result
            if (ERROR_INSUFFICIENT_BUFFER != retVal || 0 == dwBytesReturned)
            {
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // fltlib.FilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, lpBuffer, dwBytesReturned, ref dwBytesReturned, ref hFilters);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr lpBuffer = Marshal.AllocHGlobal((int)dwBytesReturned);

            try
            {
                retVal = fFilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, lpBuffer, dwBytesReturned, ref dwBytesReturned, ref hFilters);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterFindFirst Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != retVal)
            {
                Misc.GetWin32Error("FilterFindFirst");
                return false;
            }

            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "Frame ID", "Instances", "Altitude", "Filter Name");
            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "--------", "---------", "--------", "-----------");

            Print(lpBuffer);
            Marshal.FreeHGlobal(lpBuffer);

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Iterates through the subsequent filters after the first
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal virtual bool Next()
        {
            if (IntPtr.Zero == hFilters)
            {
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // First call to function to get buffer size
            // fltlib.FilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, out lpBytesReturned)
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterFindNext = Generic.GetExportAddress(hfltlib, "FilterFindNext");
            MonkeyWorks.fltlib.FilterFindNext fFilterFindNext = (MonkeyWorks.fltlib.FilterFindNext)Marshal.GetDelegateForFunctionPointer(hFilterFindNext, typeof(MonkeyWorks.fltlib.FilterFindNext));

            uint lpBytesReturned = 0;
            uint retVal = 0;
            do
            {
                try
                {
                    retVal = fFilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, ref lpBytesReturned);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] FilterFindNext Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    return false;
                }

                if (ERROR_INSUFFICIENT_BUFFER != retVal)
                {
                    break;
                }

                ////////////////////////////////////////////////////////////////////////////////
                // fltlib.FilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, lpBuffer, lpBytesReturned, out lpBytesReturned)
                ////////////////////////////////////////////////////////////////////////////////
                IntPtr lpBuffer = Marshal.AllocHGlobal((int)lpBytesReturned);
                
                try
                {
                    retVal = fFilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, lpBuffer, lpBytesReturned, ref lpBytesReturned);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] FilterFindNext Generated an Exception");
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
        /// Prints the Filters and altitudes output
        /// No Conversion Required
        /// </summary>
        /// <param name="baseAddress"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private static void Print(IntPtr baseAddress)
        {
            var info = (FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION)Marshal.PtrToStructure(baseAddress, typeof(FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION));

            uint offset = 0;
            do
            {
                IntPtr lpAltitude = new IntPtr(baseAddress.ToInt64() + info.FilterAltitudeBufferOffset);
                string altitude = Marshal.PtrToStringUni(lpAltitude, info.FilterAltitudeLength / 2);

                string alarm = "";
                uint dwAltitude = 0;
                if (uint.TryParse(altitude, out dwAltitude))
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
                string name = Marshal.PtrToStringUni(lpName, info.FilterNameLength / 2);

                Console.WriteLine("{0,8} {1,9} {2,8} {3,-20} {4,-15}", info.FrameID, info.NumberOfInstances, altitude, name, alarm);

                IntPtr updatedBase = new IntPtr(baseAddress.ToInt64() + info.NextEntryOffset);
                info = (FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION)Marshal.PtrToStructure(updatedBase, typeof(FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION));
            }
            while (0 != offset);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Detaches an instance of a minifilter
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        /// <param name="cLP"></param>
        ////////////////////////////////////////////////////////////////////////////////
        internal void FilterDetach(string filter, string volume, string instance)
        {      
            ////////////////////////////////////////////////////////////////////////////////
            // fltlib.FilterDetach(filter, volume, instance);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterDetach = Generic.GetExportAddress(hfltlib, "FilterDetach");
            MonkeyWorks.fltlib.FilterDetach fFilterDetach = (MonkeyWorks.fltlib.FilterDetach)Marshal.GetDelegateForFunctionPointer(hFilterDetach, typeof(MonkeyWorks.fltlib.FilterDetach));

            uint retVal = 0;
            try
            {
                retVal = fFilterDetach(filter, volume, instance);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterDetach Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            if (0 != retVal)
            {
                if (ERROR_PRIVILEGE_NOT_HELD == retVal)
                {
                    Console.WriteLine("[-] Privilege Not Held (Probably SeLoadDriverPrivilege)");
                    return;
                }
                else if (ERROR_FLT_DO_NOT_DETACH == retVal)
                {
                    Console.WriteLine("[-] Filter does not have a detach routine");
                    return;
                }
                Console.WriteLine("FilterDetach Failed: 0x{0}", retVal.ToString("X4"));
                return;
            }

            Console.WriteLine("[+] Filter Detached");
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Unloads a loaded minifilter
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        /// <param name="cLP"></param>
        ////////////////////////////////////////////////////////////////////////////////
        internal void FilterUnload(string filter)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // fltlib.FilterUnload(filter);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterUnload = Generic.GetExportAddress(hfltlib, "FilterUnload");
            MonkeyWorks.fltlib.FilterUnload fFilterUnload = (MonkeyWorks.fltlib.FilterUnload)Marshal.GetDelegateForFunctionPointer(hFilterUnload, typeof(MonkeyWorks.fltlib.FilterUnload));

            uint retVal = 0;
            try
            {
                retVal = fFilterUnload(filter);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterUnload Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            if (0 != retVal)
            {
                if (ERROR_PRIVILEGE_NOT_HELD == retVal)
                {
                    Console.WriteLine("[-] Privilege Not Held (Probably SeLoadDriverPrivilege)");
                    return;
                }
                else if (ERROR_FLT_DO_NOT_DETACH == retVal)
                {
                    Console.WriteLine("[-] Filter does not have a detach routine");
                    return;
                }
                Console.WriteLine("FilterUnload Failed: 0x{0}", retVal.ToString("X4"));
                return;
            }
            Console.WriteLine("[+] Filter Unloaded");
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default Deconsturctor
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        ~Filters()
        {
            if (!disposed)
            {
                Dispose();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// IDisposable - closes the handle to the filters
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public virtual void Dispose()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Closes the filter handle
            // fltlib.FilterFindClose(hFilters);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hFilterFindClose = Generic.GetExportAddress(hfltlib, "FilterFindClose");
            MonkeyWorks.fltlib.FilterFindClose fFilterFindClose = (MonkeyWorks.fltlib.FilterFindClose)Marshal.GetDelegateForFunctionPointer(hFilterFindClose, typeof(MonkeyWorks.fltlib.FilterFindClose));

            uint retVal = 0;
            try
            {
                retVal = fFilterFindClose(hFilters);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] FilterFindClose Generated an Exception");
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
