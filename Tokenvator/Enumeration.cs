using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace Tokenvator
{
    class Enumeration
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Lists interactive user sessions
        ////////////////////////////////////////////////////////////////////////////////
        public static void EnumerateInteractiveUserSessions()
        {
            Dictionary<String, UInt32> users = new Dictionary<String, UInt32>();
            IntPtr ppSessionInfo = new IntPtr();
            Int32 pCount = 0;
            wtsapi32.WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref pCount);
            for (Int32 i = 0; i < pCount; i++)
            {
                IntPtr j = new IntPtr(ppSessionInfo.ToInt32() + (i * Marshal.SizeOf(typeof(wtsapi32._WTS_SESSION_INFO))));
                wtsapi32._WTS_SESSION_INFO wtsSessionInfo = (wtsapi32._WTS_SESSION_INFO)Marshal.PtrToStructure(j, typeof(wtsapi32._WTS_SESSION_INFO));
                IntPtr ppBuffer;
                IntPtr pBytesReturned;
                if (!wtsapi32.WTSQuerySessionInformationW(IntPtr.Zero, wtsSessionInfo.SessionId, wtsapi32._WTS_INFO_CLASS.WTSUserName, out ppBuffer, out pBytesReturned))
                {
                    Console.WriteLine("[-] {0}", Marshal.GetLastWin32Error());
                    continue;
                }

                String userName = Marshal.PtrToStringUni(ppBuffer);
                if (!users.ContainsKey(userName))
                {
                    users.Add(userName, (UInt32)wtsSessionInfo.SessionId);
                }
            }
            Console.WriteLine("{0,-30}{1,-30}", "User", "SessionID");
            Console.WriteLine("{0,-30}{1,-30}", "----", "---------");
            foreach (String name in users.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", name, users[name]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Converts a TokenStatistics Pointer array to User Name
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean ConvertTokenStatisticsToUsername(Winnt._TOKEN_STATISTICS tokenStatistics, ref String userName)
        {
            IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Structs._LUID)));
            Marshal.StructureToPtr(tokenStatistics.AuthenticationId, lpLuid, false);
            if (IntPtr.Zero == lpLuid)
            {
                return false;
            }

            IntPtr ppLogonSessionData = new IntPtr();
            if (0 != secur32.LsaGetLogonSessionData(lpLuid, out ppLogonSessionData))
            {
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

            if (Environment.MachineName+"$" == Marshal.PtrToStringUni(securityLogonSessionData.UserName.Buffer) && ConvertSidToName(securityLogonSessionData.Sid, ref userName))
            {
                return true;

            }

            userName = String.Format("{0}\\{1}", Marshal.PtrToStringUni(securityLogonSessionData.LogonDomain.Buffer), Marshal.PtrToStringUni(securityLogonSessionData.UserName.Buffer));
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Converts a SID Byte array to User Name
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean ConvertSidToName(IntPtr sid, ref String userName)
        {
            StringBuilder lpName = new StringBuilder();
            UInt32 cchName = (UInt32)lpName.Capacity;
            StringBuilder lpReferencedDomainName = new StringBuilder();
            UInt32 cchReferencedDomainName = (UInt32)lpReferencedDomainName.Capacity;
            Enums._SID_NAME_USE sidNameUser;
            advapi32.LookupAccountSid(String.Empty, sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUser);

            lpName.EnsureCapacity((Int32)cchName);
            lpReferencedDomainName.EnsureCapacity((Int32)cchReferencedDomainName);
            if (advapi32.LookupAccountSid(String.Empty, sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUser))
            {
                return false;
            }
            if (String.IsNullOrEmpty(lpName.ToString()) || String.IsNullOrEmpty(lpReferencedDomainName.ToString()))
            {
                return false;
            }
            userName = lpReferencedDomainName.ToString() + "\\" + lpName.ToString();
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Finds a process per user discovered
        // ToDo: check if token is a primary token
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<String, UInt32> EnumerateTokens(Boolean findElevation)
        {
            Dictionary<String, UInt32> users = new Dictionary<String, UInt32>();
            foreach (Process p in Process.GetProcesses())
            {
                IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_LIMITED_INFORMATION, true, (UInt32)p.Id);
                if (IntPtr.Zero == hProcess)
                {
                    continue;
                }
                IntPtr hToken;
                if (!kernel32.OpenProcessToken(hProcess, (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED, out hToken))
                {
                    continue;
                }
                kernel32.CloseHandle(hProcess);
                if (findElevation)
                {
                    if (!CheckPrivileges.CheckElevation(hToken))
                    {
                        continue;
                    }
                }

                UInt32 dwLength = 0;
                Winnt._TOKEN_STATISTICS tokenStatistics = new Winnt._TOKEN_STATISTICS();
                //Split up impersonation and primary tokens
                if (Winnt.TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }

                if (!advapi32.GetTokenInformation(hToken, Enums._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    if (!advapi32.GetTokenInformation(hToken, Enums._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                    {
                        Console.WriteLine("GetTokenInformation: {0}", Marshal.GetLastWin32Error());
                        continue;
                    }
                }
                kernel32.CloseHandle(hToken);

                String userName = String.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }

                if (!users.ContainsKey(userName))
                {
                    users.Add(userName, (UInt32)p.Id);
                }
            }
            return users;
        }

        /////////////////////////////////////////////////////////////////////////////
        // Lists tokens via WMI
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<String, UInt32> EnumerateTokensWMI()
        {
            Dictionary<String, UInt32> users = new Dictionary<String, UInt32>();
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
                    String[] owner = new String[2];
                    managementObject.InvokeMethod("GetOwner", (object[])owner);
                    if (!users.ContainsKey((owner[1] + "\\" + owner[0]).ToUpper()))
                    {
                        users.Add((owner[1] + "\\" + owner[0]).ToUpper(), (UInt32)managementObject["ProcessId"]);
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
        public static Dictionary<UInt32, String> EnumerateUserProcesses(Boolean findElevation, String userAccount)
        {
            Dictionary<UInt32, String> users = new Dictionary<UInt32, String>();
            Process[] pids = Process.GetProcesses();
            Console.WriteLine("[*] Examining {0} processes", pids.Length);
            foreach (Process p in pids)
            {
                IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_LIMITED_INFORMATION, true, (UInt32)p.Id);
                if (IntPtr.Zero == hProcess)
                {
                    continue;
                }
                IntPtr hToken;
                if (!kernel32.OpenProcessToken(hProcess, (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED, out hToken))
                {
                    continue;
                }
                kernel32.CloseHandle(hProcess);

                if (findElevation && !CheckPrivileges.CheckElevation(hToken))
                {
                    continue;
                }

                UInt32 dwLength = 0;
                Winnt._TOKEN_STATISTICS tokenStatistics = new Winnt._TOKEN_STATISTICS();
                if (!advapi32.GetTokenInformation(hToken, Enums._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    if (!advapi32.GetTokenInformation(hToken, Enums._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                    {
                        continue;
                    }
                }
                kernel32.CloseHandle(hToken);

                if (Winnt.TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }

                
                String userName = String.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }
                if (userName.ToUpper() == userAccount.ToUpper())
                {
                    users.Add((UInt32)p.Id, p.ProcessName);
                    if (findElevation)
                    {
                        return users;
                    }
                }
            }
            Console.WriteLine("[*] Discovered {0} processes", users.Count);

            Dictionary<UInt32, String> sorted = new Dictionary<UInt32, String>();
            foreach (var user in users.OrderBy(u => u.Value))
            {
                sorted.Add(user.Key, user.Value);
            }
            
            return sorted;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Find processes for user via WMI
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<UInt32, String> EnumerateUserProcessesWMI(String userAccount)
        {
            Dictionary<UInt32, String> processes = new Dictionary<UInt32, String>();
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
                    String[] owner = new String[2];
                    managementObject.InvokeMethod("GetOwner", (object[])owner);
                    if ((owner[1] + "\\" + owner[0]).ToUpper() == userAccount.ToUpper())
                    {
                        processes.Add((UInt32)managementObject["ProcessId"], (String)managementObject["Name"]);
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
}