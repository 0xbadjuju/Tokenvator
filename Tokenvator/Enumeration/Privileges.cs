using System;
using System.Runtime.InteropServices;

using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Enumeration
{
    class Privileges
    {            
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

        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetTokenOwner(IntPtr hToken)
        {
            uint returnLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenOwner, IntPtr.Zero, 0, out returnLength);
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((int)returnLength);
            Ntifs._TOKEN_OWNER tokenOwner;
            try
            {
                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenOwner, lpTokenInformation, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation - Pass 2");
                    return;
                }
                tokenOwner = (Ntifs._TOKEN_OWNER)Marshal.PtrToStructure(lpTokenInformation, typeof(Ntifs._TOKEN_OWNER));
                if (IntPtr.Zero == tokenOwner.Owner)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
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
        public static void GetTokenUser(IntPtr hToken)
        {
            uint returnLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, 0, out returnLength);
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((int)returnLength);
            Ntifs._TOKEN_USER tokenUser;
            try
            {
                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenUser, lpTokenInformation, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation - Pass 2");
                    return;
                }
                tokenUser = (Ntifs._TOKEN_USER)Marshal.PtrToStructure(lpTokenInformation, typeof(Ntifs._TOKEN_USER));
                if (IntPtr.Zero == tokenUser.User[0].Sid)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }
            
            Console.WriteLine("[+] User: ");
            string sid, account;
            sid = account = string.Empty;
            _ReadSidAndName(tokenUser.User[0].Sid, out sid, out account);
            Console.WriteLine("{0,-50} {1}", sid, account);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Lists the groups associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public static bool GetTokenGroups(IntPtr hToken)
        {
            uint returnLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, 0, out returnLength);
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((int)returnLength);
            Ntifs._TOKEN_GROUPS tokenGroups;
            try
            {
                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenGroups, lpTokenInformation, returnLength, out returnLength))
                {
                    Misc.GetWin32Error("GetTokenInformation - Pass 2");
                    return false;
                }
                tokenGroups = (Ntifs._TOKEN_GROUPS)Marshal.PtrToStructure(lpTokenInformation, typeof(Ntifs._TOKEN_GROUPS));
            }
            catch (Exception ex)
            {
                Misc.GetWin32Error("GetTokenInformation - Pass 2");
                Console.WriteLine(ex.Message);
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }

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

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _ReadSidAndName(IntPtr pointer, out string sid, out string account)
        {
            sid = string.Empty;
            account = string.Empty;
            IntPtr lpSid = IntPtr.Zero;
            try
            {
                advapi32.ConvertSidToStringSid(pointer, ref lpSid);
                if (IntPtr.Zero == lpSid)
                {
                    return;
                }
                sid = Marshal.PtrToStringAuto(lpSid);

                if (!UserSessions.ConvertSidToName(pointer, out account))
                {
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                kernel32.LocalFree(lpSid);
            }
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