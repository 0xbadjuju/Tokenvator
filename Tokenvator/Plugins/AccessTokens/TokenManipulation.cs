using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

using Tokenvator.Resources;
using Tokenvator.Plugins.Enumeration;
using Tokenvator.Plugins.Execution;


using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    partial class TokenManipulation : AccessTokens
    {
        private Dictionary<uint, string> processes;

        public static List<string> validPrivileges = new List<string> { "SeAssignPrimaryTokenPrivilege",
            "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege",
            "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
            "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
            "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
            "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege",
            "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };

        ////////////////////////////////////////////////////////////////////////////////
        // Default Constructor
        ////////////////////////////////////////////////////////////////////////////////
        internal TokenManipulation(IntPtr currentProcessToken) : base(currentProcessToken)
        {
            processes = new Dictionary<uint, string>();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // IDisposable
        ////////////////////////////////////////////////////////////////////////////////
        public new void Dispose()
        {
            base.Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Default Destructor
        ////////////////////////////////////////////////////////////////////////////////
        ~TokenManipulation()
        {
            Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Assigns a token to a process
        ////////////////////////////////////////////////////////////////////////////////
        public bool AssignPrimaryToken()
        {
            ntdll._PROCESS_ACCESS_TOKEN processAccessToken = new ntdll._PROCESS_ACCESS_TOKEN
            {
                hToken = phNewToken,
                hThread = IntPtr.Zero
            };

            uint status = ntdll.NtSetInformationProcess(
                kernel32.GetCurrentProcess(),
                ntdll._PROCESS_INFORMATION_CLASS.ProcessAccessToken,
                ref processAccessToken,
                (uint)Marshal.SizeOf(typeof(ntdll._PROCESS_ACCESS_TOKEN))
            );

            if (0 != status)
            {
                Misc.GetNtError("NtSetInformationProcess", status);
                Console.WriteLine("[*] Is SeAssignPrimaryTokenPrivilege Enabled?");
                return false;
            }
            Console.WriteLine("[+] Primary Token Assigned");

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges
        ////////////////////////////////////////////////////////////////////////////////
        public void DisableAndRemoveAllTokenPrivileges()
        {
            ////////////////////////////////////////////////////////////////////////////////
            Console.WriteLine("[*] Enumerating Token Privileges");
            uint TokenInfLength = 0;
            advapi32.GetTokenInformation(hExistingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);

            if (TokenInfLength < 0 || TokenInfLength > int.MaxValue)
            {
                Misc.GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 1");
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((int)TokenInfLength);

            ////////////////////////////////////////////////////////////////////////////////
            if (!advapi32.GetTokenInformation(hExistingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, out TokenInfLength))
            {
                Misc.GetWin32Error("GetTokenInformation - 2 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 2");
            Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (Winnt._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(Winnt._TOKEN_PRIVILEGES_ARRAY));
            Marshal.FreeHGlobal(lpTokenInformation);
            Console.WriteLine("[+] Enumerated {0} Privileges", tokenPrivileges.PrivilegeCount);
            Console.WriteLine();
            Console.WriteLine("{0,-45}{1,-30}", "Privilege Name", "Enabled");
            Console.WriteLine("{0,-45}{1,-30}", "--------------", "-------");
            ////////////////////////////////////////////////////////////////////////////////
            for (int i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                int cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                if (cchName <= 0 || cchName > int.MaxValue)
                {
                    Misc.GetWin32Error("LookupPrivilegeName Pass 1");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                lpName.EnsureCapacity(cchName + 1);
                if (!advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                {
                    Misc.GetWin32Error("LookupPrivilegeName Pass 2");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };

                int pfResult = 0;
                if (!advapi32.PrivilegeCheck(hExistingToken, ref privilegeSet, out pfResult))
                {
                    Misc.GetWin32Error("PrivilegeCheck");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }
                if (Convert.ToBoolean(pfResult))
                {
                    SetTokenPrivilege(lpName.ToString(), Winnt.TokenPrivileges.SE_PRIVILEGE_NONE);
                }
                SetTokenPrivilege(lpName.ToString(), Winnt.TokenPrivileges.SE_PRIVILEGE_REMOVED);
                Marshal.FreeHGlobal(lpLuid);
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public bool DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL impersonationLevel)
        {
            if (IntPtr.Zero == hExistingToken)
                return false;

            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hWorkingToken,
                        (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        impersonationLevel,
                        Winnt._TOKEN_TYPE.TokenImpersonation,
                        out phNewToken
            ))
            {
                Misc.GetWin32Error("DuplicateTokenEx: ");
                return false;
            }

            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));
            return true;
        }

        #region Privilege Escalations
        ////////////////////////////////////////////////////////////////////////////////
        // Creates a new process as SYSTEM
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetSystem(string newProcess)
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = UserSessions.EnumerateUserProcesses(false, systemAccount.ToString());

            foreach (uint process in processes.Keys)
            {
                if (OpenProcessToken((int)process))
                {
                    Console.WriteLine(" [+] Opened {0}", process);
                    SetWorkingTokenToRemote();
                    if (DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                    {
                        SetWorkingTokenToNewToken();
                        if (StartProcessAsUser(newProcess))
                        {
                            return true;
                        }
                    }
                }
            }

            Misc.GetWin32Error("GetSystem");
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Elevates current process to SYSTEM
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetSystem()
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = UserSessions.EnumerateUserProcesses(false, systemAccount.ToString());

            foreach (uint process in processes.Keys)
            {
                if (OpenProcessToken((int)process))
                {
                    Console.WriteLine(" [+] Opened {0}", process);
                    SetWorkingTokenToRemote();
                    if (ImpersonateUser())
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a process as SYSTEM w/ Trusted Installer Group
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetTrustedInstaller(string newProcess)
        {
            Console.WriteLine("[+] Getting NT AUTHORITY\\SYSTEM privileges");
            GetSystem();
            Console.WriteLine(" [*] Running as: {0}", WindowsIdentity.GetCurrent().Name);

            Services services = new Services("TrustedInstaller");
            if (!services.StartService())
            {
                Misc.GetWin32Error("StartService");
                return false;
            }

            if (!OpenProcessToken((int)services.GetServiceProcessId()))
            {
                Misc.GetWin32Error("GetPrimaryToken");
                return false;
            }

            SetWorkingTokenToRemote();
            if (!DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
            {
                Misc.GetWin32Error("DuplicateToken");
                return false;
            }

            SetWorkingTokenToNewToken();
            if (!StartProcessAsUser(newProcess))
            {
                Misc.GetWin32Error("DuplicateToken");
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Elevates current process to SYSTEM w/ Trusted Installer Group
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetTrustedInstaller()
        {
            Console.WriteLine("[*] Getting NT AUTHORITY\\SYSTEM privileges");
            GetSystem();
            Console.WriteLine(" [+] Running as: {0}", WindowsIdentity.GetCurrent().Name);

            Services services = new Services("TrustedInstaller");
            if (!services.StartService())
            {
                Misc.GetWin32Error("StartService");
                return false;
            }

            if (OpenProcessToken((int)services.GetServiceProcessId()))
            {
                SetWorkingTokenToRemote();
                if (ImpersonateUser())
                {
                    return true;
                }
            }

            return false;
        }
        #endregion

        ////////////////////////////////////////////////////////////////////////////////
        // 
        ////////////////////////////////////////////////////////////////////////////////
        public void LogonUser(string domain, string username, string password, Winbase.LOGON_TYPE logonType, string command, string arguments)
        {
            if (!advapi32.LogonUser(username, domain, password, logonType, Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, out hExistingToken))
            {
                Misc.GetWin32Error("LogonUser");
                return;
            }
            Console.WriteLine("[+] Logged On {0}", username.TrimEnd());

            if (Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE == logonType)
            {
                if (!SetTokenSessionId(Process.GetCurrentProcess().SessionId))
                {
                    Console.WriteLine(" [-] Unable to Update Token Session ID, this is likely to cause problems with this token");
                }
            }

            if (string.IsNullOrEmpty(command))
            {
                SetWorkingTokenToRemote();
                ImpersonateUser();
            }
            else
            {
                Create createProcess;
                if (0 == Process.GetCurrentProcess().SessionId)
                    createProcess = CreateProcess.CreateProcessWithLogonW;
                else
                    createProcess = CreateProcess.CreateProcessWithTokenW;

                createProcess(hExistingToken, command, arguments);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // 
        ////////////////////////////////////////////////////////////////////////////////
        public void LogonUser(string domain, string username, string password, string groups, Winbase.LOGON_TYPE logonType, string command, string arguments)
        {
            SetWorkingTokenToSelf();
            CreateTokens ct = new CreateTokens(hWorkingToken);
            Ntifs._TOKEN_GROUPS tokenGroups;
            Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
            ct.CreateTokenGroups(domain, username, out tokenGroups, out tokenPrimaryGroup, groups.Split(','));
            /*
            TokenInformation ti = new TokenInformation(hWorkingToken);
            ti.GetTokenGroups();
            Ntifs._TOKEN_GROUPS tokenGroups = ti.tokenGroups;
            
            int extraGroups = tokenGroups.GroupCount;

            uint groupsAttributes = (uint)(Winnt.SE_GROUP_ENABLED | Winnt.SE_GROUP_ENABLED_BY_DEFAULT | Winnt.SE_GROUP_MANDATORY);

            Ntifs._TOKEN_GROUPS tokenGroupsCopy = new Ntifs._TOKEN_GROUPS();
            tokenGroupsCopy.Initialize();

            for (int i = 0; i < tokenGroups.GroupCount; i++)
            {
                tokenGroupsCopy.Groups[i] = tokenGroups.Groups[i];
            }

            foreach (string group in groups.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries))
            {
                Console.WriteLine(group);
                string d = Environment.MachineName;
                string groupname = group;
                if (group.Contains(@"\"))
                {
                    string[] split = group.Split('\\');
                    d = split[0];
                    groupname = split[1];
                }
                Console.WriteLine(groupname);
                string sid = new NTAccount(d, groupname).Translate(typeof(SecurityIdentifier)).Value;
                Console.WriteLine(sid);
                tokenGroupsCopy.Groups[++extraGroups].Sid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                Console.WriteLine(extraGroups);
                CreateTokens.InitializeSid(sid, ref tokenGroupsCopy.Groups[extraGroups].Sid);
                tokenGroupsCopy.Groups[extraGroups].Attributes = groupsAttributes;
            }
            tokenGroupsCopy.GroupCount = extraGroups;
            */

            if (!advapi32.LogonUserExExW(
                username, domain, password, 
                logonType, Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, 
                ref tokenGroups, out hExistingToken, 
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
            {
                Misc.GetWin32Error("LogonUserExExW");
                return;
            }
            Console.WriteLine("[+] Logged On {0}", username.TrimEnd());

            if (Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE == logonType)
            {
                SetWorkingTokenToRemote();
                if (!SetTokenSessionId(Process.GetCurrentProcess().SessionId))
                {
                    Console.WriteLine(" [-] Unable to Update Token Session ID, this is likely to cause problems with this token");
                }
            }

            if (string.IsNullOrEmpty(command))
            {
                SetWorkingTokenToRemote();
                ImpersonateUser();
            }
            else
            {
                Create createProcess;
                if (0 == Process.GetCurrentProcess().SessionId)
                    createProcess = CreateProcess.CreateProcessWithLogonW;
                else
                    createProcess = CreateProcess.CreateProcessWithTokenW;

                createProcess(hExistingToken, command, arguments);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Can be use to remove groups, adding groups would require a new token 
        // Next Release
        //https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokengroups
        ////////////////////////////////////////////////////////////////////////////////
        public void SetTokenGroup(string group, bool isSID)
        {
            var tokenGroups = new Ntifs._TOKEN_GROUPS();
            tokenGroups.Initialize();

            if (!DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
            {
                return;
            }
            SetWorkingTokenToNewToken();

            TokenInformation ti = new TokenInformation(hWorkingToken);
            ti.GetTokenGroups();
            for (int i = 0; i < ti.tokenGroups.GroupCount; i++)
            {
                tokenGroups.Groups[i].Sid = ti.tokenGroups.Groups[i].Sid;
                tokenGroups.Groups[i].Attributes = ti.tokenGroups.Groups[i].Attributes;
                Console.WriteLine(tokenGroups.Groups[i].Sid);
            }
            tokenGroups.GroupCount = ti.tokenGroups.GroupCount;

            if (!isSID)
            {
                Console.WriteLine("Group:     {0}", group);
                string domain = Environment.MachineName;
                if (group.Contains(@"\"))
                {
                    string[] split = group.Split('\\');
                    domain = split[0];
                    group = split[1];
                }
                group = new NTAccount(domain, group).Translate(typeof(SecurityIdentifier)).Value;
            }
            Console.WriteLine("Group SID: {0}", group);
            ++tokenGroups.GroupCount;

            if (!CreateTokens.InitializeSid("S-1-5-21-258464558-1780981397-2849438727-1010", ref tokenGroups.Groups[tokenGroups.GroupCount].Sid))
            {
                return;
            }
            tokenGroups.Groups[tokenGroups.GroupCount].Attributes = (uint)Winnt.SE_GROUP_ENABLED;
            CreateTokens ct = new CreateTokens(hWorkingToken);

            string userName = WindowsIdentity.GetCurrent().Name;
            userName = userName.Split('\\')[1];

            //ct.CreateTokenGroups(userName, out Ntifs._TOKEN_GROUPS tg, out Winnt._TOKEN_PRIMARY_GROUP tpg);

            tokenGroups = ti.tokenGroups;

            uint returnLength;
            if (!advapi32.AdjustTokenGroups(hWorkingToken, false, ref tokenGroups, (uint)Marshal.SizeOf(tokenGroups), ref ti.tokenGroups, out returnLength))
            {
                Misc.GetWin32Error("AdjustTokenGroups");
                return;
            }

            ti.GetTokenGroups();

            Console.WriteLine(returnLength);


        }

        ////////////////////////////////////////////////////////////////////////////////
        // 
        ////////////////////////////////////////////////////////////////////////////////
        public void SetThreadTokenPrivilege(string privilege, Winnt.TokenPrivileges attribute)
        {
            foreach (uint t in threads)
            {
                Console.WriteLine("[*] Thread ID: " + t);
                if (OpenThreadToken(t, Winnt.TOKEN_ALL_ACCESS))
                {
                    SetWorkingTokenToThreadToken();
                    SetTokenPrivilege(privilege, attribute);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public bool SetTokenPrivilege(string privilege, Winnt.TokenPrivileges attribute)
        {
            Console.WriteLine("[*] Adjusting Token Privilege {0} => {1}", privilege, attribute);
            ////////////////////////////////////////////////////////////////////////////////
            Winnt._LUID luid = new Winnt._LUID();
            if (!advapi32.LookupPrivilegeValue(null, privilege, ref luid))
            {
                Misc.GetWin32Error("LookupPrivilegeValue");
                return false;
            }
            Console.WriteLine(" [+] Recieved luid");

            ////////////////////////////////////////////////////////////////////////////////
            Winnt._LUID_AND_ATTRIBUTES luidAndAttributes = new Winnt._LUID_AND_ATTRIBUTES
            {
                Luid = luid,
                Attributes = (uint)attribute
            };
            Winnt._TOKEN_PRIVILEGES newState = new Winnt._TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = luidAndAttributes
            };
            Winnt._TOKEN_PRIVILEGES previousState = new Winnt._TOKEN_PRIVILEGES();
            Console.WriteLine(" [*] AdjustTokenPrivilege");
            uint returnLength;
            if (!advapi32.AdjustTokenPrivileges(hWorkingToken, false, ref newState, (uint)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                Misc.GetWin32Error("AdjustTokenPrivileges");
                return false;
            }

            Console.WriteLine(" [+] Adjusted Privilege: {0}", privilege);
            Console.WriteLine(" [+] Privilege State: {0}", attribute);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Updates the token session ID to the specified session
        ////////////////////////////////////////////////////////////////////////////////
        public bool SetTokenSessionId(int sessionId)
        {
            bool exists, enabled;
            SetWorkingTokenToSelf();
            TokenInformation.CheckTokenPrivilege(hWorkingToken, Winnt.SE_TCB_NAME, out exists, out enabled);

            if (!exists)
            {
                Console.WriteLine("[-] SeTcbPrivilege Does Not Exist On Token");
                return false;
            }

            SetWorkingTokenToRemote();
            if (!enabled && !SetTokenPrivilege(Winnt.SE_TCB_NAME, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED))
            {
                Console.WriteLine("[-] Enable SeTcbPrivilege Failed ");
                return false;
            }

            Console.WriteLine("[*] Updating Token Session ID to {0}", sessionId);

            GCHandle handle = new GCHandle();
            try
            {
                handle = GCHandle.Alloc(sessionId, GCHandleType.Pinned);
                if (!advapi32.SetTokenInformation(
                    hWorkingToken,
                    Winnt._TOKEN_INFORMATION_CLASS.TokenSessionId,
                    handle.AddrOfPinnedObject(),
                    sizeof(uint))
                )
                {
                    Misc.GetWin32Error("SetTokenInformation");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                if (null != handle && handle.IsAllocated)
                    handle.Free();
            }
            return true;
        }
    }
}
