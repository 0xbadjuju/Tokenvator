using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

using Tokenvator.Resources;

namespace Tokenvator.Plugins.MiniFilters
{
    class Filters : IDisposable
    {
        protected IntPtr hFilters = IntPtr.Zero;
        //private FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION info;

        public Filters()
        {
            Console.WriteLine();
        }

        internal virtual void First()
        {
            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "Frame ID", "Instances", "Altitude", "Filter Name");
            Console.WriteLine("{0,8} {1,9} {2,8} {3,-10}", "--------", "---------", "--------", "-----------");

            uint dwBytesReturned = 0;
            uint result = fltlib.FilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, ref dwBytesReturned, ref hFilters);

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

            uint result = 0;
            do
            {
                uint lpBytesReturned = 0;
                if (2147942522 != fltlib.FilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, out lpBytesReturned))
                {
                    break;
                }
                IntPtr lpBuffer = Marshal.AllocHGlobal((int)lpBytesReturned);
                result = fltlib.FilterFindNext(hFilters, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, lpBuffer, lpBytesReturned, out lpBytesReturned);
                                
                Print(lpBuffer);
                Marshal.FreeHGlobal(lpBuffer);
            }
            while (0 == result);
        }

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

        internal static void FilterDetach(CommandLineParsing cLP)
        {
            string filter;
            if (!cLP.GetData("filter", out filter))
            {
                Console.WriteLine("[-] /Filter: Not Specified");
                return;
            }

            string instance;
            if (!cLP.GetData("instance", out instance))
            {
                Console.WriteLine("[-] /Instance: Not Specified");
                return;
            }

            string volume;
            if (!cLP.GetData("volume", out volume))
            {
                Console.WriteLine("[-] /Volume: Not Specified");
                return;
            }

            uint result = fltlib.FilterDetach(filter, volume, instance);
            if (0 != result)
            {
                if (2147943714 == result)
                {
                    Console.WriteLine("[-] Privilege Not Held (Probably SeLoadDriverPrivilege)");
                    return;
                }
                else if (2149515280 == result)
                {
                    Console.WriteLine("[-] Filter does not have a detach routine");
                    return;
                }
                Console.WriteLine("FilterDetach Failed: 0x{0}", result.ToString("X4"));
                return;
            }

            Console.WriteLine("[+] Filter Detached");
        }

        internal static void Unload(CommandLineParsing cLP)
        {
            string filter;
            if (!cLP.GetData("filter", out filter))
            {
                Console.WriteLine("[-] Filter Not Specified");
                return;
            }

            uint result = fltlib.FilterUnload(filter);
            if (0 != result)
            {
                if (2147943714 == result)
                {
                    Console.WriteLine("[-] Privilege Not Held (Probably SeLoadDriverPrivilege)");
                    return;
                }
                else if (2149515280 == result)
                {
                    Console.WriteLine("[-] Filter does not have a detach routine");
                    return;
                }
                Console.WriteLine("FilterUnload Failed: 0x{0}", result.ToString("X4"));
                return;
            }
            Console.WriteLine("[+] Filter Unloaded");
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
