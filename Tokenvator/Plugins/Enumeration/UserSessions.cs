using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

using Tokenvator.Resources;
using Tokenvator.Plugins.AccessTokens;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.Enumeration
{
    class UserSessions
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Lists interactive user sessions
        ////////////////////////////////////////////////////////////////////////////////
        public static void EnumerateInteractiveUserSessions()
        {
            Dictionary<string, uint> users = new Dictionary<string, uint>();
            IntPtr ppSessionInfo = new IntPtr();
            int pCount = 0;
            wtsapi32.WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref pCount);
            for (int i = 0; i < pCount; i++)
            {
                IntPtr j = new IntPtr(ppSessionInfo.ToInt64() + (i * Marshal.SizeOf(typeof(wtsapi32._WTS_SESSION_INFO))));
                wtsapi32._WTS_SESSION_INFO wtsSessionInfo = (wtsapi32._WTS_SESSION_INFO)Marshal.PtrToStructure(j, typeof(wtsapi32._WTS_SESSION_INFO));
                IntPtr ppBuffer, pBytesReturned;
                ppBuffer = pBytesReturned = IntPtr.Zero;
                if (!wtsapi32.WTSQuerySessionInformationW(IntPtr.Zero, wtsSessionInfo.SessionId, wtsapi32._WTS_INFO_CLASS.WTSUserName, out ppBuffer, out pBytesReturned))
                {
                    Console.WriteLine("[-] {0}", Marshal.GetLastWin32Error());
                    continue;
                }

                string userName = Marshal.PtrToStringUni(ppBuffer);
                if (!users.ContainsKey(userName))
                {
                    users.Add(userName, (uint)wtsSessionInfo.SessionId);
                }
            }
            Console.WriteLine("{0,-30}{1,-30}", "User", "SessionID");
            Console.WriteLine("{0,-30}{1,-30}", "----", "---------");
            foreach (string name in users.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", name, users[name]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Converts a TokenStatistics Pointer array to User Name
        ////////////////////////////////////////////////////////////////////////////////
        private static bool ConvertTokenStatisticsToUsername(Winnt._TOKEN_STATISTICS tokenStatistics, ref string userName)
        {
            IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Winnt._LUID)));
            Marshal.StructureToPtr(tokenStatistics.AuthenticationId, lpLuid, false);
            if (IntPtr.Zero == lpLuid)
            {
                return false;
            }

            IntPtr ppLogonSessionData = new IntPtr();
            if (0 != secur32.LsaGetLogonSessionData(lpLuid, out ppLogonSessionData))
            {
                Misc.GetWin32Error("LsaGetLogonSessionData");
                return false;
            }

            if (IntPtr.Zero == ppLogonSessionData)
            {
                return false;
            }

            ntsecapi._SECURITY_LOGON_SESSION_DATA securityLogonSessionData = (ntsecapi._SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(ntsecapi._SECURITY_LOGON_SESSION_DATA));
            if (IntPtr.Zero == securityLogonSessionData.Sid || IntPtr.Zero == securityLogonSessionData.UserName.Buffer || IntPtr.Zero == securityLogonSessionData.LogonDomain.Buffer)
            {
                return false;
            }
            
            string usernameBuffer = Marshal.PtrToStringUni(securityLogonSessionData.UserName.Buffer);

            if (Environment.MachineName+"$" == usernameBuffer && ConvertSidToName(securityLogonSessionData.Sid, out userName))
            {
                return true;

            }

            userName = string.Format("{0}\\{1}", Marshal.PtrToStringUni(securityLogonSessionData.LogonDomain.Buffer), usernameBuffer);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Converts a SID Byte array to User Name
        ////////////////////////////////////////////////////////////////////////////////
        internal static bool ConvertSidToName(IntPtr sid, out string userName)
        {
            StringBuilder sbUserName = new StringBuilder();

            string lpSystemName = string.Empty;
            StringBuilder lpName = new StringBuilder();
            uint cchName = (uint)lpName.Capacity;
            StringBuilder lpReferencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)lpReferencedDomainName.Capacity;
            Winnt._SID_NAME_USE sidNameUse = new Winnt._SID_NAME_USE();
            advapi32.LookupAccountSid(lpSystemName, sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUse);

            lpName.EnsureCapacity((int)cchName + 1);
            lpReferencedDomainName.EnsureCapacity((int)cchReferencedDomainName + 1);

            byte[] bsid = new byte[16];
            Marshal.Copy(sid, bsid, 0, 16);
            bool retVal = advapi32.LookupAccountSid(lpSystemName, sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUse);

            if (!retVal && 0 == lpName.Length)
            {
                Misc.GetWin32Error("LookupAccountSid");
            }

            if (lpReferencedDomainName.Length > 0)
            {
                sbUserName.Append(lpReferencedDomainName);
            }

            if (sbUserName.Length > 0)
            {
                sbUserName.Append(@"\");
            }

            if (lpName.Length > 0)
            {
                sbUserName.Append(lpName);
            }

            userName = sbUserName.ToString();

            if (string.IsNullOrEmpty(userName))
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Borrowed from Sharpire
        ////////////////////////////////////////////////////////////////////////////////
        internal static void Tasklist()
        {
            Dictionary<int, string> owners = new Dictionary<int, string>();
            ManagementScope scope = new ManagementScope("\\\\.\\root\\cimv2");
            scope.Connect();
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            foreach (ManagementObject managementObject in objectCollection)
            {
                string name = "";
                string[] owner = new string[2];
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
                owners[Convert.ToInt32(managementObject["Handle"])] = name;
            }

            List<string[]> lines = new List<string[]>();
            foreach (Process process in Process.GetProcesses())
            {
                string architecture;
                int workingSet;
                bool isWow64Process;
                try
                {
                    kernel32.IsWow64Process(process.Handle, out isWow64Process);
                    if (isWow64Process)
                        architecture = "x64";
                    else
                        architecture = "x86";
                }
                catch (Exception)
                {
                    architecture = "N/A";
                }
                workingSet = (int)(process.WorkingSet64 / 1000000);

                string userName = "";
                try
                {
                    if (!owners.TryGetValue(process.Id, out userName))
                        userName = "False";
                }
                catch
                {
                    userName = "<Exception>";
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

            //https://stackoverflow.com/questions/232395/how-do-i-sort-a-two-dimensional-array-in-c
            Comparer<int> comparer = Comparer<int>.Default;
            Array.Sort<String[]>(linesArray, (x, y) => comparer.Compare(Convert.ToInt32(x[1]), Convert.ToInt32(y[1])));

            List<string> sortedLines = new List<string>();
            string[] headerArray = { "ProcessName", "PID", "Arch", "UserName", "MemUsage" };
            sortedLines.Add(string.Format("{0,-30} {1,-8} {2,-6} {3,-28} {4,8}", headerArray));
            foreach (string[] line in linesArray)
            {
                sortedLines.Add(string.Format("{0,-30} {1,-8} {2,-6} {3,-28} {4,8} M", line));
            }
            Console.WriteLine(string.Join("\n", sortedLines.ToArray()));
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Finds a process per user discovered
        // ToDo: check if token is a primary token
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<string, uint> EnumerateTokens(bool findElevation)
        {
            Dictionary<string, uint> users = new Dictionary<string, uint>();
            foreach (Process p in Process.GetProcesses())
            {
                IntPtr hProcess = kernel32.OpenProcess(Winnt.PROCESS_QUERY_LIMITED_INFORMATION, true, (uint)p.Id);
                if (IntPtr.Zero == hProcess)
                {
                    continue;
                }
                IntPtr hToken;
                if (!kernel32.OpenProcessToken(hProcess, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, out hToken))
                {
                    continue;
                }
                kernel32.CloseHandle(hProcess);
                if (findElevation)
                {
                    if (!TokenInformation.CheckElevation(hToken))
                    {
                        continue;
                    }
                }

                uint dwLength = 0;
                Winnt._TOKEN_STATISTICS tokenStatistics = new Winnt._TOKEN_STATISTICS();
                //Split up impersonation and primary tokens
                if (Winnt._TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }

                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                    {
                        Console.WriteLine("GetTokenInformation: {0}", Marshal.GetLastWin32Error());
                        continue;
                    }
                }
                kernel32.CloseHandle(hToken);

                string userName = string.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }

                if (!users.ContainsKey(userName))
                {
                    users.Add(userName, (uint)p.Id);
                }
            }
            return users;
        }

        /////////////////////////////////////////////////////////////////////////////
        // Lists tokens via WMI
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<string, uint> EnumerateTokensWMI()
        {
            Dictionary<string, uint> users = new Dictionary<string, uint>();
            List<ManagementObject> systemProcesses = new List<ManagementObject>();
            ManagementScope scope = new ManagementScope("\\\\.\\root\\cimv2");
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
        // Find processes for a user via Tokens
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<uint, string> EnumerateUserProcesses(bool findElevation, string targetAccount)
        {
            Dictionary<uint, string> users = new Dictionary<uint, string>();
            Process[] pids = Process.GetProcesses();
            Console.WriteLine("[*] Examining {0} processes", pids.Length);
            foreach (Process p in pids)
            {
                IntPtr hProcess = kernel32.OpenProcess(Winnt.PROCESS_QUERY_LIMITED_INFORMATION, true, (uint)p.Id);
                if (IntPtr.Zero == hProcess)
                {
                    continue;
                }
                IntPtr hToken;
                if (!kernel32.OpenProcessToken(hProcess, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, out hToken))
                {
                    continue;
                }
                kernel32.CloseHandle(hProcess);

                if (findElevation && !TokenInformation.CheckElevation(hToken))
                {
                    continue;
                }

                uint dwLength = 0;
                Winnt._TOKEN_STATISTICS tokenStatistics = new Winnt._TOKEN_STATISTICS();
                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                    {
                        continue;
                    }
                }
                kernel32.CloseHandle(hToken);

                if (Winnt._TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }


                string userName = string.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }
                if (userName.Contains(targetAccount, StringComparison.OrdinalIgnoreCase))
                {
                    users.Add((uint)p.Id, p.ProcessName);
                    if (findElevation)
                    {
                        return users;
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
        // Find processes for user via WMI
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