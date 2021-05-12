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
    partial class Tokens : IDisposable
    {
        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        private readonly IntPtr currentProcessToken;
        private Dictionary<uint, string> processes;

        internal delegate bool Create(IntPtr phNewToken, string newProcess, string arguments); 

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

        List<uint> threads = new List<uint>();

        ////////////////////////////////////////////////////////////////////////////////
        // Default Constructor
        ////////////////////////////////////////////////////////////////////////////////
        internal Tokens(IntPtr currentProcessToken)
        {
            hWorkingToken = new IntPtr();
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            processes = new Dictionary<uint, string>();

            this.currentProcessToken = currentProcessToken;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // IDisposable
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            if (IntPtr.Zero != phNewToken)  
                kernel32.CloseHandle(phNewToken);
            if (IntPtr.Zero != hExistingToken)
                kernel32.CloseHandle(hExistingToken);
            if (IntPtr.Zero != hWorkingToken)
                kernel32.CloseHandle(hWorkingToken);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Default Destructor
        ////////////////////////////////////////////////////////////////////////////////
        ~Tokens()
        {
            Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Assigns a token to a process
        ////////////////////////////////////////////////////////////////////////////////
        public bool AddTokenPrivilege(string privilege)
        {
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        Winnt.TOKEN_ALL_ACCESS,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityDelegation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                Misc.GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));
            kernel32.CloseHandle(hExistingToken);

            SetWorkingTokenToNewToken();
            SetTokenPrivilege(privilege, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED_BY_DEFAULT | Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);

            EnumerateTokenPrivileges();

            return true;
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
                        hExistingToken,
                        (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        impersonationLevel,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                Misc.GetWin32Error("DuplicateTokenEx: ");
                return false;
            }

            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));
            return true;
        }

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
                    if (DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                        if (StartProcessAsUser(newProcess))
                            return true;
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
                    if (ImpersonateUser())
                        return true;
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

            if (!DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
            {
                Misc.GetWin32Error("DuplicateToken");
                return false;
            }

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
                if (ImpersonateUser())
                    return true;

            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Impersonates the token from a specified processId
        ////////////////////////////////////////////////////////////////////////////////
        public virtual bool ImpersonateUser()
        {
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                Misc.GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                Misc.GetWin32Error("ImpersonateLoggedOnUser: ");
                return false;
            }

            Console.WriteLine("[+] Operating as {0}", WindowsIdentity.GetCurrent().Name);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public void LogonUser(string domain, string username, string password, Winbase.LOGON_TYPE logonType, string input, string start)
        {
            if (!advapi32.LogonUser(username, domain, password, logonType, Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, out hExistingToken))
            {
                Console.WriteLine(" [-] Logon User");
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

            string next = Misc.NextItem(ref input);

            if (next.ToLower() == start.ToLower())
            {
                ImpersonateUser();
            }
            else
            {
                Create createProcess;
                if (0 == Process.GetCurrentProcess().SessionId)
                    createProcess = CreateProcess.CreateProcessWithLogonW;
                else
                    createProcess = CreateProcess.CreateProcessWithTokenW;

                string arguments;
                Misc.FindExe(ref next, out arguments);

                createProcess(hExistingToken, next, arguments);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hToken to a processes primary token
        ////////////////////////////////////////////////////////////////////////////////
        public virtual bool OpenProcessToken(int processId)
        {
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if (!windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator)
                && !windowsPrincipal.IsInRole(WindowsBuiltInRole.SystemOperator))
            {
                Console.WriteLine("[-] Administrator privileges required");
                return false;
            }

            IntPtr hProcess = kernel32.OpenProcess(Winnt.PROCESS_QUERY_INFORMATION, false, (uint)processId);
            if (IntPtr.Zero == hProcess)
            {
                Misc.GetWin32Error("OpenProcess");
                return false;
            }
            Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));

            if (!kernel32.OpenProcessToken(hProcess, Winnt.TOKEN_ALL_ACCESS, out hExistingToken))
            {
                if (!kernel32.OpenProcessToken(hProcess, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, out hExistingToken))
                {
                    Console.WriteLine(" [-] Unable to Open Process Token");
                    Misc.GetWin32Error("OpenProcessToken");
                    kernel32.CloseHandle(hProcess);
                    return false;
                }
            }
            Console.WriteLine("[*] Recieved Token Handle 0x{0}", hExistingToken.ToString("X4"));
            kernel32.CloseHandle(hProcess);
            return true;
        } 

        ////////////////////////////////////////////////////////////////////////////////
        // List all process threads
        ////////////////////////////////////////////////////////////////////////////////
        public bool ListThreads(int processId)
        {
            if (0 == processId)
            {
                processId = Process.GetCurrentProcess().Id;
            }

            IntPtr hSnapshot = kernel32.CreateToolhelp32Snapshot(TiHelp32.TH32CS_SNAPTHREAD, 0);

            if (IntPtr.Zero == hSnapshot)
            {
                Misc.GetWin32Error("CreateToolhelp32Snapshot");
                return false;
            }

            TiHelp32.tagTHREADENTRY32 threadyEntry32 = new TiHelp32.tagTHREADENTRY32()
            {
                dwSize = (uint)Marshal.SizeOf(typeof(TiHelp32.tagTHREADENTRY32))
            };

            if (!kernel32.Thread32First(hSnapshot, ref threadyEntry32))
            {
                Misc.GetWin32Error("Thread32First");
                return false;
            }           

            if(threadyEntry32.th32OwnerProcessID == processId)
                threads.Add(threadyEntry32.th32ThreadID);

            while(kernel32.Thread32Next(hSnapshot, ref threadyEntry32))
            {
                if (threadyEntry32.th32OwnerProcessID == processId)
                    threads.Add(threadyEntry32.th32ThreadID);
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Lists the users for threads
        ////////////////////////////////////////////////////////////////////////////////
        public void GetThreadUsers()
        {
            foreach(uint t in threads)
            {
                Console.WriteLine("[*] Thread ID: " + t);
                if (_OpenThreadToken(t))
                {
                    Privileges.GetTokenUser(hWorkingThreadToken);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Opens a thread token
        ////////////////////////////////////////////////////////////////////////////////
        private bool _OpenThreadToken(uint threadId)
        {
            IntPtr hToken = new IntPtr();
            IntPtr hThread = kernel32.OpenThread(ProcessThreadsApi.ThreadSecurityRights.THREAD_QUERY_INFORMATION, false, threadId);

            if(IntPtr.Zero == hThread)
            {
                Misc.GetWin32Error("OpenThread");
                return false;
            }

            bool retVal = kernel32.OpenThreadToken(hThread, Winnt.TOKEN_QUERY, false, ref hWorkingThreadToken);

            if (!retVal || IntPtr.Zero == hWorkingThreadToken)
            {
                return false;
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a new process with the duplicated token
        ////////////////////////////////////////////////////////////////////////////////
        public bool StartProcessAsUser(string newProcess)
        {
            Create createProcess;
            if (0 == Process.GetCurrentProcess().SessionId)
                createProcess = CreateProcess.CreateProcessWithLogonW;
            else
                createProcess = CreateProcess.CreateProcessWithTokenW;
            string arguments = string.Empty;
            Misc.FindExe(ref newProcess, out arguments);

            if (!createProcess(phNewToken, newProcess, arguments))
            {
                return false;
            }
            return true;
        }
    }
}
