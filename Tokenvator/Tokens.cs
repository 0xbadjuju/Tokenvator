using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    class Tokens : IDisposable
    {
        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        private IntPtr currentProcessToken;
        private Dictionary<UInt32, String> processes;

        internal delegate Boolean Create(IntPtr phNewToken, String newProcess, String arguments); 

        public static List<String> validPrivileges = new List<string> { "SeAssignPrimaryTokenPrivilege", 
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
        public Tokens()
        {
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            processes = new Dictionary<UInt32, String>();
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if (!windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("[-] Administrator privileges required");
            }

            currentProcessToken = new IntPtr();
            kernel32.OpenProcessToken(Process.GetCurrentProcess().Handle, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
            SetTokenPrivilege(ref currentProcessToken, Constants.SE_DEBUG_NAME, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);
        }

        protected Tokens(Boolean rt)
        {
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            processes = new Dictionary<UInt32, String>();

            currentProcessToken = new IntPtr();
            kernel32.OpenProcessToken(Process.GetCurrentProcess().Handle, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
        }

        public void Dispose()
        {
            if (IntPtr.Zero != phNewToken)  
                kernel32.CloseHandle(phNewToken);
            if (IntPtr.Zero != hExistingToken)
                kernel32.CloseHandle(hExistingToken);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Default Destructor
        ////////////////////////////////////////////////////////////////////////////////
        ~Tokens()
        {
            Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Calls CreateProcessWithTokenW
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean StartProcessAsUser(Int32 processId, String newProcess)
        {
            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

            Create createProcess;
            if (0 == Process.GetCurrentProcess().SessionId)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }
            String arguments = String.Empty;
            FindExe(ref newProcess, out arguments);

            if (!createProcess(phNewToken, newProcess, arguments))
            {
                return false;
            }
            return true;
        }

        protected void FindExe(ref String command, out String arguments)
        {
             arguments = "";
            if (command.Contains(" "))
            {
                String[] commandAndArguments = command.Split(new String[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                command = commandAndArguments.First();
                arguments = String.Join(" ", commandAndArguments.Skip(1).Take(commandAndArguments.Length - 1).ToArray());
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Impersonates the token from a specified processId
        ////////////////////////////////////////////////////////////////////////////////
        public virtual Boolean ImpersonateUser(Int32 processId)
        {
            Console.WriteLine("[*] Impersonating {0}", processId);
            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));
            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                GetWin32Error("ImpersonateLoggedOnUser: ");
                return false;
            }
            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a new process as SYSTEM
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetSystem(String newProcess)
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = Enumeration.EnumerateUserProcesses(false, systemAccount.ToString());
            
            foreach (UInt32 process in processes.Keys)
            {
                if (StartProcessAsUser((Int32)process, newProcess))
                {
                    return true;
                }
            }
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Elevates current process to SYSTEM
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetSystem()
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = Enumeration.EnumerateUserProcesses(false, systemAccount.ToString());
            
            foreach (UInt32 process in processes.Keys)
            {
                if (ImpersonateUser((Int32)process))
                {
                    return true;
                }
            }
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a process as SYSTEM w/ Trusted Installer Group
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetTrustedInstaller(String newProcess)
        {
            Console.WriteLine("[+] Getting NT AUTHORITY\\SYSTEM privileges");
            GetSystem();
            Console.WriteLine(" [*] Running as: {0}", WindowsIdentity.GetCurrent().Name);
            
            Services services = new Services("TrustedInstaller");
            if (!services.StartService())
            {
                GetWin32Error("StartService");
                return false;
            }

            if (!StartProcessAsUser((Int32)services.GetServiceProcessId(), newProcess))
            {
                GetWin32Error("StartProcessAsUser");
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Elevates current process to SYSTEM w/ Trusted Installer Group
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetTrustedInstaller()
        {
            Console.WriteLine("[*] Getting NT AUTHORITY\\SYSTEM privileges");
            GetSystem();
            Console.WriteLine(" [+] Running as: {0}", WindowsIdentity.GetCurrent().Name);

            Services services = new Services("TrustedInstaller");
            if (!services.StartService())
            {
                GetWin32Error("StartService");
                return false;
            }

            if (!ImpersonateUser((Int32)services.GetServiceProcessId()))
            {
                GetWin32Error("ImpersonateUser");
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hToken to a processes primary token
        ////////////////////////////////////////////////////////////////////////////////
        public virtual Boolean GetPrimaryToken(UInt32 processId, String name)
        {
            //Originally Set to true
            IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_INFORMATION, true, processId);
            if (hProcess == IntPtr.Zero)
            {
                return false;
            }
            Console.WriteLine("[+] Recieved Handle for: {0} ({1})", name, processId);
            Console.WriteLine(" [+] Process Handle: 0x{0}", hProcess.ToString("X4"));

            if (!kernel32.OpenProcessToken(hProcess, Constants.TOKEN_ALT, out hExistingToken))
            {
                return false;   
            }
            Console.WriteLine(" [+] Primary Token Handle: 0x{0}", hExistingToken.ToString("X4"));
            kernel32.CloseHandle(hProcess);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Opens a thread token
        ////////////////////////////////////////////////////////////////////////////////
        private static IntPtr OpenThreadTokenChecked()
        {
            IntPtr hToken = new IntPtr();
            Console.WriteLine("[*] Opening Thread Token");
            if (!kernel32.OpenThreadToken(kernel32.GetCurrentThread(), (Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES), false, ref hToken))
            {
                Console.WriteLine(" [-] OpenTheadToken Failed");
                Console.WriteLine(" [*] Impersonating Self");
                if (!advapi32.ImpersonateSelf(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                {
                    GetWin32Error("ImpersonateSelf");
                    return IntPtr.Zero;
                }
                Console.WriteLine(" [+] Impersonated Self");
                Console.WriteLine(" [*] Retrying");
                if (!kernel32.OpenThreadToken(kernel32.GetCurrentThread(), (Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES), false, ref hToken))
                {
                    GetWin32Error("OpenThreadToken");
                    return IntPtr.Zero;
                }
            }
            Console.WriteLine(" [+] Recieved Thread Token Handle: 0x{0}", hToken.ToString("X4"));
            return hToken;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void SetTokenPrivilege(ref IntPtr hToken, String privilege, Winnt.TokenPrivileges attribute)
        {
            if (!validPrivileges.Contains(privilege))
            {
                Console.WriteLine("[-] Invalid Privilege Specified");
                return;
            }

            Console.WriteLine("[*] Adjusting Token Privilege");
            ////////////////////////////////////////////////////////////////////////////////
            Winnt._LUID luid = new Winnt._LUID();
            if (!advapi32.LookupPrivilegeValue(null, privilege, ref luid))
            {
                GetWin32Error("LookupPrivilegeValue");
                return;
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
            UInt32 returnLength = 0;
            if (!advapi32.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                GetWin32Error("AdjustTokenPrivileges");
                return;
            }

            Console.WriteLine(" [+] Adjusted Privilege: {0}", privilege);
            Console.WriteLine(" [+] Privilege State: {0}", attribute);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void NukeTokenPrivilege(ref IntPtr hToken)
        {
            Winnt._TOKEN_PRIVILEGES newState = new Winnt._TOKEN_PRIVILEGES();
            Winnt._TOKEN_PRIVILEGES previousState = new Winnt._TOKEN_PRIVILEGES();
            Console.WriteLine(" [*] AdjustTokenPrivilege");
            UInt32 returnLength = 0;
            if (!advapi32.AdjustTokenPrivileges(hToken, true, ref newState, (UInt32)Marshal.SizeOf(typeof(Winnt._TOKEN_PRIVILEGES)), ref previousState, out returnLength))
            {
                GetWin32Error("AdjustTokenPrivileges");
            }
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges
        ////////////////////////////////////////////////////////////////////////////////
        public static void DisableAndRemoveAllTokenPrivileges(ref IntPtr hToken)
        {
            ////////////////////////////////////////////////////////////////////////////////
            Console.WriteLine("[*] Enumerating Token Privileges");
            UInt32 TokenInfLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);

            if (TokenInfLength < 0 || TokenInfLength > Int32.MaxValue)
            {
                GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 1");
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength);

            ////////////////////////////////////////////////////////////////////////////////
            if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, out TokenInfLength))
            {
                GetWin32Error("GetTokenInformation - 2 " + TokenInfLength);
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
            for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                Int32 cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                if (cchName <= 0 || cchName > Int32.MaxValue)
                {
                    GetWin32Error("LookupPrivilegeName Pass 1");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                lpName.EnsureCapacity(cchName + 1);
                if (!advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                {
                    GetWin32Error("LookupPrivilegeName Pass 2");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };

                Int32 pfResult = 0;
                if (!advapi32.PrivilegeCheck(hToken, ref privilegeSet, out pfResult))
                {
                    GetWin32Error("PrivilegeCheck");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }
                if (Convert.ToBoolean(pfResult))
                {
                    SetTokenPrivilege(ref hToken, lpName.ToString(), Winnt.TokenPrivileges.SE_PRIVILEGE_NONE);
                }
                SetTokenPrivilege(ref hToken, lpName.ToString(), Winnt.TokenPrivileges.SE_PRIVILEGE_REMOVED);
                Marshal.FreeHGlobal(lpLuid);
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges
        ////////////////////////////////////////////////////////////////////////////////
        public static void EnumerateTokenPrivileges(IntPtr hToken)
        {
            ////////////////////////////////////////////////////////////////////////////////
            Console.WriteLine("[*] Enumerating Token Privileges");
            UInt32 TokenInfLength;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);

            if (TokenInfLength < 0 || TokenInfLength > Int32.MaxValue)  
            {
                GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 1");
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength) ;
            
            ////////////////////////////////////////////////////////////////////////////////
            if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, out TokenInfLength))
            {
                GetWin32Error("GetTokenInformation - 2 " + TokenInfLength);
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
            for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                Int32 cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                if (cchName <= 0 || cchName > Int32.MaxValue)  
                {
                    GetWin32Error("LookupPrivilegeName Pass 1");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                lpName.EnsureCapacity(cchName + 1);
                if (!advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                {
                    GetWin32Error("LookupPrivilegeName Pass 2");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };

                Int32 pfResult = 0;
                if (!advapi32.PrivilegeCheck(hToken, ref privilegeSet, out pfResult))
                {
                    GetWin32Error("PrivilegeCheck");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }
                Console.WriteLine("{0,-45}{1,-30}", lpName.ToString(), Convert.ToBoolean(pfResult));
                Marshal.FreeHGlobal(lpLuid);
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetNtError(String location, UInt32 ntError)
        {
            UInt32 win32Error = ntdll.RtlNtStatusToDosError(ntError);
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception((Int32)win32Error).Message);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetWin32Error(String location)
        {
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
        }
    }
}
