using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    class TokenInformation : AccessTokens
    {
        public Winnt._TOKEN_SOURCE tokenSource;
        public IntPtr hTokenSource;
        public Ntifs._TOKEN_USER tokenUser;
        public IntPtr hTokenUser;
        public Ntifs._TOKEN_GROUPS tokenGroups;
        public IntPtr hTokenGroups;
        public Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges;
        public IntPtr hTokenPrivileges;
        public Ntifs._TOKEN_OWNER tokenOwner;
        public IntPtr hTokenOwner;
        public Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
        public IntPtr hTokenPrimaryGroup;
        public Winnt._TOKEN_DEFAULT_DACL tokenDefaultDacl;
        public IntPtr hTokenDefaultDacl;
        public Winnt._TOKEN_DEFAULT_DACL_ACL tokenDefaultDaclAcl;

        public TokenInformation(IntPtr hToken) : base(hToken)
        {
        }

        ~TokenInformation()
        {
            Marshal.FreeHGlobal(hTokenSource);
            Marshal.FreeHGlobal(hTokenUser);
            Marshal.FreeHGlobal(hTokenGroups);
            Marshal.FreeHGlobal(hTokenPrivileges);
            Marshal.FreeHGlobal(hTokenOwner);
            Marshal.FreeHGlobal(hTokenPrimaryGroup);
            Marshal.FreeHGlobal(hTokenDefaultDacl);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static bool PrintElevation(IntPtr hToken)
        {

            int output = -1;
            if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenElevationType, ref output))
            {
                Misc.GetWin32Error("TokenElevationType");
                return false;
            }

            switch ((Winnt.TOKEN_ELEVATION_TYPE)output)
            {
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    Console.WriteLine("[+] TokenElevationTypeDefault");
                    Console.WriteLine("[*] Token: Not Split");
                    //Console.WriteLine("ProcessIntegrity: Medium/Low");
                    return false;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    Console.WriteLine("[+] TokenElevationTypeFull");
                    Console.WriteLine("[*] Token: Split");
                    Console.WriteLine("[+] ProcessIntegrity: High");
                    return true;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    Console.WriteLine("[-] TokenElevationTypeLimited");
                    Console.WriteLine("[*] Token: Split");
                    Console.WriteLine("[-] ProcessIntegrity: Medium/Low");
                    Console.WriteLine("[!] Hint: Try to Bypass UAC");
                    return false;
                default:
                    Console.WriteLine("[-] Unknown integrity {0}", output);
                    Console.WriteLine("[!] Trying anyway");
                    return true;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static bool CheckElevation(IntPtr hToken)
        {
            int output = -1;
            if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenElevationType, ref output))
            {
                Misc.GetWin32Error("TokenElevationType");
                return false;
            }

            switch ((Winnt.TOKEN_ELEVATION_TYPE)output)
            {
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:;
                    return false;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    return true;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    return false;
                default:
                    return true;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static bool GetElevationType(IntPtr hToken, out Winnt._TOKEN_TYPE tokenType)
        {
            int output = -1;
            if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenType, ref output))
            {
                Misc.GetWin32Error("TokenType");
                tokenType = 0;
                return false;
            }

            switch ((Winnt._TOKEN_TYPE)output)
            {
                case Winnt._TOKEN_TYPE.TokenPrimary:
                    Console.WriteLine("[+] Primary Token");
                    tokenType = Winnt._TOKEN_TYPE.TokenPrimary;
                    return true;
                case Winnt._TOKEN_TYPE.TokenImpersonation:
                    tokenType = Winnt._TOKEN_TYPE.TokenImpersonation;
                    if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, ref output))
                    {
                        return false;
                    }
                    switch ((Winnt._SECURITY_IMPERSONATION_LEVEL)output)
                    {
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:
                            Console.WriteLine("[+] Anonymous Token");
                            return true;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:
                            Console.WriteLine("[+] Identification Token");
                            return true;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:
                            Console.WriteLine("[+] Impersonation Token");
                            return true;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:
                            Console.WriteLine("[+] Delegation Token");
                            return true;
                        default:
                            Console.WriteLine("[-] Unknown Impersionation Type");
                            return false;
                    }
                default:
                    Console.WriteLine("[-] Unknown Type {0}", output);
                    tokenType = 0;
                    return false;
            }
        }

        #region ThreadInformation
        ////////////////////////////////////////////////////////////////////////////////
        // Lists the users for threads
        ////////////////////////////////////////////////////////////////////////////////
        public void GetThreadUsers()
        {
            foreach (uint t in threads)
            {
                Console.WriteLine("[*] Thread ID: " + t);
                if (OpenThreadToken(t, Winnt.TOKEN_QUERY))
                {
                    using (TokenInformation ti = new TokenInformation(hWorkingThreadToken))
                    {
                        ti.SetWorkingTokenToSelf();
                        ti.GetTokenUser();
                    }
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Lists the users for threads
        ////////////////////////////////////////////////////////////////////////////////
        public void GetThreadPrivileges()
        {
            foreach (uint t in threads)
            {
                Console.WriteLine("[*] Thread ID: " + t);
                if (OpenThreadToken(t, Winnt.TOKEN_QUERY))
                {
                    using (TokenInformation ti = new TokenInformation(hWorkingThreadToken))
                    {
                        ti.SetWorkingTokenToSelf();
                        ti.GetTokenUser();
                        ti.GetTokenPrivileges();
                    }
                }
            }
        }
        #endregion

        #region GetTokenInformation
        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenSource()
        {
            uint returnLength;
            advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenSource, IntPtr.Zero, 0, out returnLength);
            hTokenSource = Marshal.AllocHGlobal((int)returnLength);
            try
            {
                if (!advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenSource, hTokenSource, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation (TokenSource) - Pass 2");
                    return;
                }
                tokenSource = (Winnt._TOKEN_SOURCE)Marshal.PtrToStructure(hTokenSource, typeof(Winnt._TOKEN_SOURCE));
                if (0 == tokenSource.SourceName.Length)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation (TokenSource) - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }

            Console.WriteLine("[+] Source: " + new string(tokenSource.SourceName));
            return;
        }
        
        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenUser()
        {
            uint returnLength;
            advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, 0, out returnLength);
            hTokenUser = Marshal.AllocHGlobal((int)returnLength);
            
            try
            {
                if (!advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenUser, hTokenUser, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation (TokenUser) - Pass 2");
                    return;
                }
                tokenUser = (Ntifs._TOKEN_USER)Marshal.PtrToStructure(hTokenUser, typeof(Ntifs._TOKEN_USER));
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation (TokenUser) - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }
            
            Console.WriteLine("[+] User: ");
            string sid, account;
            sid = account = string.Empty;
            _ReadSidAndName(tokenUser.User.Sid, out sid, out account);
            Console.WriteLine("{0,-50} {1}", sid, account);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Lists the groups associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetTokenGroups()
        {
            uint returnLength;
            advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, 0, out returnLength);
            hTokenGroups = Marshal.AllocHGlobal((int)returnLength);
            try
            {
                if (!advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenGroups, hTokenGroups, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation (TokenGroups) - Pass 2");
                    return false;
                }
                tokenGroups = (Ntifs._TOKEN_GROUPS)Marshal.PtrToStructure(hTokenGroups, typeof(Ntifs._TOKEN_GROUPS));

                Console.WriteLine("[+] Enumerated {0} Groups: ", tokenGroups.GroupCount);
                for (int i = 0; i < tokenGroups.GroupCount; i++)
                {
                    string sid, account;
                    sid = account = string.Empty;
                    _ReadSidAndName(tokenGroups.Groups[i].Sid, out sid, out account);
                    Console.WriteLine("{0,-50} {1}", sid, account);
                }
                return true;

            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation (TokenGroups) - Pass 2");
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenPrivileges()
        {
            ////////////////////////////////////////////////////////////////////////////////
            uint TokenInfLength;
            Console.WriteLine("[*] Enumerating Token Privileges");
            advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);

            if (TokenInfLength < 0 || TokenInfLength > int.MaxValue)
            {
                Misc.GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation (TokenPrivileges) - Pass 1");
            hTokenPrivileges = Marshal.AllocHGlobal((int)TokenInfLength);

            ////////////////////////////////////////////////////////////////////////////////
            if (!advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, hTokenPrivileges, TokenInfLength, out TokenInfLength))
            {
                Misc.GetWin32Error("GetTokenInformation (TokenPrivileges) - 2 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 2");
            tokenPrivileges = (Winnt._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(hTokenPrivileges, typeof(Winnt._TOKEN_PRIVILEGES_ARRAY));
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
                if (!advapi32.PrivilegeCheck(hWorkingToken, ref privilegeSet, out pfResult))
                {
                    Misc.GetWin32Error("PrivilegeCheck");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }
                Console.WriteLine("{0,-45}{1,-30}", lpName.ToString(), Convert.ToBoolean(pfResult));
                Marshal.FreeHGlobal(lpLuid);
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenOwner()
        {
            uint returnLength;
            advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenOwner, IntPtr.Zero, 0, out returnLength);
            hTokenOwner = Marshal.AllocHGlobal((int)returnLength);
            try
            {
                if (!advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenOwner, hTokenOwner, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation (TokenOwner) - Pass 2");
                    return;
                }
                tokenOwner = (Ntifs._TOKEN_OWNER)Marshal.PtrToStructure(hTokenOwner, typeof(Ntifs._TOKEN_OWNER));
                if (IntPtr.Zero == tokenOwner.Owner)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation (TokenOwner) - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }

            Console.WriteLine("[+] Owner: ");
            string sid, account;
            sid = account = string.Empty;
            _ReadSidAndName(tokenOwner.Owner, out sid, out account);
            Console.WriteLine("{0,-50} {1}", sid, account);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenPrimaryGroup()
        {
            uint returnLength;
            advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, IntPtr.Zero, 0, out returnLength);
            hTokenPrimaryGroup = Marshal.AllocHGlobal((int)returnLength);
            try
            {
                if (!advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, hTokenPrimaryGroup, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation (TokenPrimaryGroup) - Pass 2");
                    return;
                }
                tokenPrimaryGroup = (Winnt._TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(hTokenPrimaryGroup, typeof(Winnt._TOKEN_PRIMARY_GROUP));
                if (IntPtr.Zero == tokenPrimaryGroup.PrimaryGroup)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation (TokenPrimaryGroup) - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }

            string primaryGroupSid, primaryGroupName;
            _ReadSidAndName(tokenPrimaryGroup.PrimaryGroup, out primaryGroupSid, out primaryGroupName);
            Console.WriteLine("[+] Primary Group: ");
            Console.WriteLine("{0,-50} {1}", primaryGroupSid, primaryGroupName);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenDefaultDacl()
        {
            uint returnLength;
            advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenDefaultDacl, IntPtr.Zero, 0, out returnLength);
            hTokenDefaultDacl = Marshal.AllocHGlobal((int)returnLength);
            try
            {
                if (!advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenDefaultDacl, hTokenDefaultDacl, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation (TokenDefaultDacl) - Pass 2");
                    return;
                }
                tokenDefaultDacl = (Winnt._TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(hTokenDefaultDacl, typeof(Winnt._TOKEN_DEFAULT_DACL));
                if (IntPtr.Zero == tokenDefaultDacl.DefaultDacl)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
                tokenDefaultDaclAcl = (Winnt._TOKEN_DEFAULT_DACL_ACL)Marshal.PtrToStructure(hTokenDefaultDacl, typeof(Winnt._TOKEN_DEFAULT_DACL_ACL));
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation (TokenDefaultDacl - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }

            string primaryGroup = Marshal.PtrToStringUni(tokenPrimaryGroup.PrimaryGroup);
            Console.WriteLine("[+] ACL Count: {0}", tokenDefaultDaclAcl.DefaultDacl.AceCount);
            return;
        }
        #endregion

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static void _ReadSidAndName(IntPtr pointer, out string sid, out string account)
        {
            sid = string.Empty;
            account = string.Empty;
            IntPtr lpSid = IntPtr.Zero;
            try
            {
                Ntifs._SID structSid = (Ntifs._SID)Marshal.PtrToStructure(pointer, typeof(Ntifs._SID));
                bool retVal = advapi32.ConvertSidToStringSid(ref structSid, ref lpSid);
                if (!retVal || IntPtr.Zero == lpSid)
                {
                    Misc.GetWin32Error("ConvertSidToStringSid");
                    return;
                }
                sid = Marshal.PtrToStringAuto(lpSid);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                kernel32.LocalFree(lpSid);
            }

            try
            {
                account = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
            }
            catch (IdentityNotMappedException ex)
            {
                account = ex.Message;
            }
            /*
            if (!UserSessions.ConvertSidToName(pointer, out account))
            {
                return;
            }
            */

        }

        ////////////////////////////////////////////////////////////////////////////////
        // Checks if a Privilege Exists and is Enabled
        ////////////////////////////////////////////////////////////////////////////////
        public static bool CheckTokenPrivilege(IntPtr hToken, string privilegeName, out bool exists, out bool enabled)
        {
            exists = false;
            enabled = false;
            ////////////////////////////////////////////////////////////////////////////////
            uint TokenInfLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);
            if (TokenInfLength <= 0 || TokenInfLength > int.MaxValue)
            {
                Misc.GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return false;
            }
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((int)TokenInfLength);

            ////////////////////////////////////////////////////////////////////////////////
            if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, out TokenInfLength))
            {
                Misc.GetWin32Error("GetTokenInformation - 2 " + TokenInfLength);
                return false;
            }
            Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (Winnt._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(Winnt._TOKEN_PRIVILEGES_ARRAY));
            Marshal.FreeHGlobal(lpTokenInformation);

            ////////////////////////////////////////////////////////////////////////////////
            for (int i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                System.Text.StringBuilder lpName = new System.Text.StringBuilder();
                int cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);
                try
                {
                    advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                    if (cchName <= 0 || cchName > int.MaxValue)
                    {
                        Misc.GetWin32Error("LookupPrivilegeName Pass 1");
                        continue;
                    }

                    lpName.EnsureCapacity(cchName + 1);
                    if (!advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                    {
                        Misc.GetWin32Error("LookupPrivilegeName Pass 2");
                        continue;
                    }

                    if (lpName.ToString() != privilegeName)
                    {
                        continue;
                    }
                    exists = true;

                    Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                    {
                        PrivilegeCount = 1,
                        Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                        Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                    };

                    int pfResult = 0;
                    if (!advapi32.PrivilegeCheck(hToken, ref privilegeSet, out pfResult))
                    {
                        Misc.GetWin32Error("PrivilegeCheck");
                        continue;
                    }
                    enabled = Convert.ToBoolean(pfResult);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return false;
                }
                finally
                {
                    Marshal.FreeHGlobal(lpLuid);
                }
            }
            Console.WriteLine();
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Private function to query a token with an enumeration result
        ////////////////////////////////////////////////////////////////////////////////
        private static bool _QueryTokenInformation(IntPtr hToken, Winnt._TOKEN_INFORMATION_CLASS informationClass, ref int dwTokenInformation)
        {
            uint tokenInformationLength = (uint)Marshal.SizeOf(typeof(uint));
            IntPtr lpTokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(uint)));
            try
            {
                uint returnLength = 0;
                if (!advapi32.GetTokenInformation(hToken, informationClass, lpTokenInformation, tokenInformationLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation");
                    return false;
                }
                dwTokenInformation = Marshal.ReadInt32(lpTokenInformation);
            }
            catch(Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }
            return true;
        }
    }
}