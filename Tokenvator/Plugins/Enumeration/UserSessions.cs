using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

using Tokenvator.Resources;
using Tokenvator.Plugins.AccessTokens;

//using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

using DInvoke.DynamicInvoke;
using System.Runtime.ExceptionServices;
using System.Security;

namespace Tokenvator.Plugins.Enumeration
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    sealed class UserSessions
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Lists interactive user sessions
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public static void EnumerateInteractiveUserSessions()
        {
            IntPtr hwtsapi32 = Generic.GetPebLdrModuleEntry("wtsapi32.dll");
            if (IntPtr.Zero == hwtsapi32)
            {
                hwtsapi32 = Generic.LoadModuleFromDisk("wtsapi32.dll");
                if (IntPtr.Zero == hwtsapi32)
                {
                    Console.WriteLine("Unable to load wtsapi32.dll");
                    return;
                }
            }

            ////////////////////////////////////////////////////////////////////////////////
            //wtsapi32.WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref pCount);
            ////////////////////////////////////////////////////////////////////////////////

            Dictionary<string, uint> users = new Dictionary<string, uint>();
            IntPtr ppSessionInfo = new IntPtr();
            uint pCount = 0;
            
            IntPtr hWTSEnumerateSessionsW = Generic.GetExportAddress(hwtsapi32, "WTSEnumerateSessionsW");
            MonkeyWorks.wtsapi32.WTSEnumerateSessionsW fWTSEnumerateSessionsW = (MonkeyWorks.wtsapi32.WTSEnumerateSessionsW)Marshal.GetDelegateForFunctionPointer(hWTSEnumerateSessionsW, typeof(MonkeyWorks.wtsapi32.WTSEnumerateSessionsW));
            
            bool retVal = false;
            try
            {
                retVal = fWTSEnumerateSessionsW(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref pCount);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] IsWow64Proces Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("WTSEnumerateSessionsW");
                return;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // Iterate through the returned count
            // wtsapi32.WTSQuerySessionInformationW(IntPtr.Zero, wtsSessionInfo.SessionId, wtsapi32._WTS_INFO_CLASS.WTSUserName, out ppBuffer, out pBytesReturned)
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hWTSQuerySessionInformationW = Generic.GetExportAddress(hwtsapi32, "WTSQuerySessionInformationW");
            MonkeyWorks.wtsapi32.WTSQuerySessionInformationW fWTSQuerySessionInformationW = (MonkeyWorks.wtsapi32.WTSQuerySessionInformationW)Marshal.GetDelegateForFunctionPointer(hWTSQuerySessionInformationW, typeof(MonkeyWorks.wtsapi32.WTSQuerySessionInformationW));

            for (int i = 0; i < pCount; i++)
            {
                IntPtr j = new IntPtr(ppSessionInfo.ToInt64() + (i * Marshal.SizeOf(typeof(MonkeyWorks.wtsapi32._WTS_SESSION_INFO))));
                MonkeyWorks.wtsapi32._WTS_SESSION_INFO wtsSessionInfo = (MonkeyWorks.wtsapi32._WTS_SESSION_INFO)Marshal.PtrToStructure(j, typeof(MonkeyWorks.wtsapi32._WTS_SESSION_INFO));
                IntPtr ppBuffer, pBytesReturned;
                ppBuffer = pBytesReturned = IntPtr.Zero;

                try
                {
                    retVal = fWTSQuerySessionInformationW(IntPtr.Zero, wtsSessionInfo.SessionId, MonkeyWorks.wtsapi32._WTS_INFO_CLASS.WTSUserName, ref ppBuffer, ref pBytesReturned);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] WTSQuerySessionInformationW Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    continue;
                }

                if (!retVal)
                {
                    Misc.GetWin32Error("WTSQuerySessionInformationW");
                    continue;
                }

                string userName = Marshal.PtrToStringUni(ppBuffer);
                if (!users.ContainsKey(userName))
                {
                    users.Add(userName, (uint)wtsSessionInfo.SessionId);
                }
            }

            Console.WriteLine();
            Console.WriteLine("{0,-30}{1,-30}", "User", "SessionID");
            Console.WriteLine("{0,-30}{1,-30}", "----", "---------");
            foreach (string name in users.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", name, users[name]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Emulates tasklist /v
        /// Borrowed from Sharpire
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// Not converting the WMI calls
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal static void Tasklist()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // kernel32.IsWow64Process(process.Handle, out isWow64Process);
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hKernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hIsWow64Process = Generic.GetExportAddress(hKernel32, "IsWow64Process");
            MonkeyWorks.kernel32.IsWow64Process fIsWow64Process = (MonkeyWorks.kernel32.IsWow64Process)Marshal.GetDelegateForFunctionPointer(hIsWow64Process, typeof(MonkeyWorks.kernel32.IsWow64Process));

            Console.WriteLine("[*] Running");

            ////////////////////////////////////////////////////////////////////////////////
            // Query WMI for a list of all running processes and get's the process owner
            ////////////////////////////////////////////////////////////////////////////////
            Dictionary<int, string> owners = new Dictionary<int, string>();
            ManagementScope scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            using (ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query))
            {
                using (ManagementObjectCollection objectCollection = objectSearcher.Get())
                {
                    foreach (ManagementObject managementObject in objectCollection)
                    {
                        Console.Write(".");
                        string name = "";
                        string[] owner = new string[2];
                        try
                        {
                            managementObject.InvokeMethod("GetOwner", (object[])owner);
                            if (owner[0] != null)
                            {
                                name = owner[1] + "\\" + owner[0];
                            }
                            else
                            {
                                name = "N/A";
                            }
                            managementObject.InvokeMethod("GetOwner", (object[])owner);
                        }
                        catch (Exception ex)
                        {
                            if (!ex.Message.Equals("Not found", StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("[-] InvokeMethod Generated an Exception");
                                Console.WriteLine("[-] {0}", ex);
                            }
                            name = "N/A";
                        }
                        owners[Convert.ToInt32(managementObject["Handle"])] = name;
                    }
                }
            }
            Console.WriteLine();

            ////////////////////////////////////////////////////////////////////////////////
            // Get the list of processes and query if it is a x86 or x64 process
            ////////////////////////////////////////////////////////////////////////////////
            List<string[]> lines = new List<string[]>();
            foreach (Process process in Process.GetProcesses())
            {
                string architecture = "N/A";
                int workingSet;
                bool isWow64Process = false;
                try
                {
                    fIsWow64Process(process.Handle, ref isWow64Process);
                    if (isWow64Process)
                        architecture = "x64";
                    else
                        architecture = "x86";
                }
                catch (Exception ex)
                {
                    if (!ex.Message.Equals("Access is denied", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("[-] IsWow64Proces Generated an Exception");
                        Console.WriteLine("[-] {0}", ex);
                    }
                }
                workingSet = (int)(process.WorkingSet64 / 1000000);

                string userName = "";
                try
                {
                    if (!owners.TryGetValue(process.Id, out userName))
                        userName = "False";
                }
                catch (Exception ex)
                {
                    userName = ex.Message;
                }

                lines.Add(
                    new string[] {process.ProcessName,
                        process.Id.ToString(),
                        architecture,
                        userName,
                        Convert.ToString(workingSet)
                    }
                );

            }
            string[][] linesArray = lines.ToArray();

            ////////////////////////////////////////////////////////////////////////////////
            // Sort the data
            // https://stackoverflow.com/questions/232395/how-do-i-sort-a-two-dimensional-array-in-c
            ////////////////////////////////////////////////////////////////////////////////

            Comparer<int> comparer = Comparer<int>.Default;
            Array.Sort<string[]>(linesArray, (x, y) => comparer.Compare(Convert.ToInt32(x[1]), Convert.ToInt32(y[1])));

            ////////////////////////////////////////////////////////////////////////////////
            // Print the sorted and formated information
            ////////////////////////////////////////////////////////////////////////////////
            List<string> sortedLines = new List<string>();
            string[] headerArray = { "ProcessName", "PID", "Arch", "UserName", "MemUsage" };
            sortedLines.Add(string.Format("{0,-30} {1,-8} {2,-6} {3,-28} {4,8}", headerArray));
            headerArray = new string[] { "-----------", "---", "----", "--------", "--------" };
            sortedLines.Add(string.Format("{0,-30} {1,-8} {2,-6} {3,-28} {4,8}", headerArray));
            foreach (string[] line in linesArray)
            {
                sortedLines.Add(string.Format("{0,-30} {1,-8} {2,-6} {3,-28} {4,8} M", line));
            }
            Console.WriteLine(string.Join("\n", sortedLines.ToArray()));
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Finds a process per user discovered
        /// </summary>
        /// <param name="findElevation"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<string, uint> EnumerateTokens(bool findElevation)
        {
            Dictionary<string, uint> users = new Dictionary<string, uint>();
            foreach (Process p in Process.GetProcesses())
            {
                using (TokenInformation ti = new TokenInformation(IntPtr.Zero))
                {
                    ti.OpenProcessToken(p.Id);
                    ti.SetWorkingTokenToRemote();
                    ti.GetTokenElevation(false);
                    if (findElevation)
                    {
                        if (!ti.GetTokenElevation(false))
                        {
                            continue;
                        }
                    }
                    string userName = ti.GetTokenUser(false);

                    if (!users.ContainsKey(userName))
                    {
                        users.Add(userName, (uint)p.Id);
                    }
                }
            }
            return users;
        }

        /////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Lists tokens via WMI
        /// Could built in .Net Methods
        /// No plans to convert
        /// </summary>
        /// <returns>Return a unique list of users on the system</returns>
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<string, uint> EnumerateTokensWMI()
        {
            Dictionary<string, uint> users = new Dictionary<string, uint>();
            List<ManagementObject> systemProcesses = new List<ManagementObject>();
            ManagementScope scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            if (!scope.IsConnected)
            {
                Console.WriteLine("[-] Failed to connect to WMI");
            }

            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            Console.WriteLine("[*] Examining " + objectCollection.Count + " processes");
            foreach (ManagementObject managementObject in objectCollection)
            {
                try
                {
                    string[] owner = new string[2];
                    managementObject.InvokeMethod("GetOwner", (object[])owner);
                    if (!users.ContainsKey((owner[1] + "\\" + owner[0]).ToUpper()))
                    {
                        users.Add((owner[1] + "\\" + owner[0]).ToUpper(), (uint)managementObject["ProcessId"]);
                    }
                }
                catch (ManagementException error)
                {
                    Console.WriteLine("[-] " + error);
                }
            }
            return users;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Find processes for a user via Tokens
        /// Being phased out
        /// P/Invokes removed and pulls from TokenInformation instead
        /// </summary>
        /// <param name="targetAccount"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<uint, string> EnumerateUserProcesses(string targetAccount)
        {
            Dictionary<uint, string> users = new Dictionary<uint, string>();
            Process[] pids = Process.GetProcesses();
            Console.WriteLine("[*] Examining {0} processes", pids.Length);

            using (TokenInformation ti = new TokenInformation(IntPtr.Zero))
            {
                foreach (Process p in pids)
                {
                    ti.OpenProcessToken(p.Id, false);
                    ti.SetWorkingTokenToRemote();
                    string userName = ti.GetTokenUser(false);
                    if (userName.Contains(targetAccount, StringComparison.OrdinalIgnoreCase))
                    {
                        users.Add((uint)p.Id, p.ProcessName);
                    }
                }
            }
            Console.WriteLine("[*] Discovered {0} processes", users.Count);

            Dictionary<uint, string> sorted = new Dictionary<uint, string>();
            foreach (var user in users.OrderBy(u => u.Value))
            {
                sorted.Add(user.Key, user.Value);
            }
            
            return sorted;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Find processes for user via WMI
        /// Not converting the WMI calls
        /// </summary>
        /// <param name="userAccount"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<uint, string> EnumerateUserProcessesWMI(string userAccount)
        {
            Dictionary<uint, string> processes = new Dictionary<uint, string>();
            List<ManagementObject> systemProcesses = new List<ManagementObject>();
            ManagementScope scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            if (!scope.IsConnected)
            {
                Console.WriteLine("[-] Failed to connect to WMI");
            }

            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            Console.WriteLine("[*] Examining {0} processes", objectCollection.Count);
            foreach (ManagementObject managementObject in objectCollection)
            {
                try
                {
                    string[] owner = new string[2];
                    managementObject.InvokeMethod("GetOwner", (object[])owner);
                    if ((owner[1] + "\\" + owner[0]).Contains(userAccount, StringComparison.OrdinalIgnoreCase))
                    {
                        processes.Add((uint)managementObject["ProcessId"], (string)managementObject["Name"]);
                    }
                }
                catch (ManagementException error)
                {
                    Console.WriteLine("[-] " + error);
                }
            }
            Console.WriteLine("[*] Discovered {0} processes", processes.Count);
            return processes;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    // https://stackoverflow.com/questions/444798/case-insensitive-containsstring
    ////////////////////////////////////////////////////////////////////////////////
    public static class StringExtensions
    {
        public static bool Contains(this string source, string toCheck, StringComparison comp)
        {
            if (!string.IsNullOrEmpty(source))
                return source.IndexOf(toCheck, comp) >= 0;
            else
                return false;
        }
    }
}