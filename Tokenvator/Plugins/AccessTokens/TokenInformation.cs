using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

using DInvoke.DynamicInvoke;

using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    class TokenInformation : AccessTokens
    {
        public bool tiDisposed = false;

        public Winnt._TOKEN_SOURCE tokenSource;
        public Ntifs._TOKEN_USER tokenUser;
        public Ntifs._TOKEN_GROUPS tokenGroups;
        public Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges;
        public Ntifs._TOKEN_OWNER tokenOwner;
        public Winnt._TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
        public Winnt._TOKEN_DEFAULT_DACL tokenDefaultDacl;
        public Winnt._TOKEN_DEFAULT_DACL_ACL tokenDefaultDaclAcl;

        public TokenInformation(IntPtr hToken) : base(hToken)
        {
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default destructor
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        ~TokenInformation()
        {
            if (!tiDisposed)
            {
                Dispose();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// IDisposable to free the allocated pointers
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            tiDisposed = true;

            base.Dispose();
        }

        #region ThreadInformation
        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Lists the users for threads
        /// No Conversions Required 
        /// </summary>
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
        /// <summary>
        /// Lists the users for threads
        /// No Conversions Required 
        /// </summary>
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
        /// <summary>
        /// Checks and Prints the elevation type of the token
        /// No Conversions Required
        /// https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        /// </summary>
        /// <param name="hToken"></param>
        /// <returns>Return true if the token is elevated</returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetTokenElevation(bool printResults)
        {
            IntPtr hTokenElevationType = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenElevationType);
            if (IntPtr.Zero == hTokenElevationType)
            {
                return false;
            }

            int output = Marshal.ReadInt32(hTokenElevationType);

            switch ((Winnt.TOKEN_ELEVATION_TYPE)output)
            {
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    if (printResults)
                    {
                        Console.WriteLine("[+] TokenElevationTypeDefault");
                        Console.WriteLine("[*] Token: Not Split");
                        Console.WriteLine("[+] ProcessIntegrity: High");
                    }
                    return true;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    if (printResults)
                    {
                        Console.WriteLine("[+] TokenElevationTypeFull");
                        Console.WriteLine("[*] Token: Split");
                        Console.WriteLine("[+] ProcessIntegrity: High");
                    }
                    return true;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    if (printResults)
                    {
                        Console.WriteLine("[-] TokenElevationTypeLimited");
                        Console.WriteLine("[*] Token: Split");
                        Console.WriteLine("[-] ProcessIntegrity: Medium/Low");
                        Console.WriteLine("[!] Hint: Try to Bypass UAC");
                    }
                    return false;
                default:
                    if (printResults)
                    {
                        Console.WriteLine("[-] Unknown integrity {0}", output);
                    }
                    return false;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Prints the token and impersonation type of the token
        /// No Conversions Required
        /// </summary>
        /// <param name="hToken"></param>
        /// <param name="tokenType"></param>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenType()
        {
            int output = -1;
            IntPtr hTokenType = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenType);
            try
            {
                output = Marshal.ReadInt32(hTokenType);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ReadInt32 Generated an Exception");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenType);
            }

            switch ((Winnt._TOKEN_TYPE)output)
            {
                case Winnt._TOKEN_TYPE.TokenPrimary:
                    Console.WriteLine("[+] Primary Token");
                    return;

                case Winnt._TOKEN_TYPE.TokenImpersonation:
                    hTokenType = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
                    try
                    {
                        output = Marshal.ReadInt32(hTokenType);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] ReadInt32 Generated an Exception");
                        Console.WriteLine(ex.Message);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(hTokenType);
                    }

                    switch ((Winnt._SECURITY_IMPERSONATION_LEVEL)output)
                    {
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:
                            Console.WriteLine("[+] Anonymous Token");
                            return;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:
                            Console.WriteLine("[+] Identification Token");
                            return;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:
                            Console.WriteLine("[+] Impersonation Token");
                            return;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:
                            Console.WriteLine("[+] Delegation Token");
                            return;
                        default:
                            Console.WriteLine("[-] Unknown Impersionation Type");
                            return;
                    }
                default:
                    Console.WriteLine("[-] Unknown Type {0}", output);
                    return;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Displays the source of a token (user32, advapi, system)
        /// P/Invokes moved to _GetTokenInformation 
        /// advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenSource, IntPtr.Zero, 0, out returnLength);
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenSource()
        {
            IntPtr hTokenSource = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenSource);
            try
            {
                tokenSource = (Winnt._TOKEN_SOURCE)Marshal.PtrToStructure(hTokenSource, typeof(Winnt._TOKEN_SOURCE));
                if (0 == tokenSource.SourceName.Length)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenSource);
            }

            Console.WriteLine("[+] Source: " + new string(tokenSource.SourceName));
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Displays the users associated with a token
        /// P/Invokes moved to _GetTokenInformation 
        /// advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, 0, out returnLength);
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenUser()
        {
            IntPtr hTokenUser = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenUser);
            try
            {
                tokenUser = (Ntifs._TOKEN_USER)Marshal.PtrToStructure(hTokenUser, typeof(Ntifs._TOKEN_USER));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenUser);
            }
            
            Console.WriteLine("[+] User: ");
            string sid, account;
            _ReadSidAndName(tokenUser.User.Sid, out sid, out account);
            Console.WriteLine("{0,-50} {1}", sid, account);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Displays the groups associated with a token
        /// P/Invokes moved to _GetTokenInformation 
        /// advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, 0, out returnLength);
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool GetTokenGroups()
        {
            IntPtr hTokenGroups = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenGroups);
            try
            {
                tokenGroups = (Ntifs._TOKEN_GROUPS)Marshal.PtrToStructure(hTokenGroups, typeof(Ntifs._TOKEN_GROUPS));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenGroups);
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
        /// <summary>
        /// Prints the tokens privileges
        /// 
        /// advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        public void GetTokenPrivileges()
        {
            Console.WriteLine("[*] Enumerating Token Privileges");
            IntPtr hTokenPrivileges = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges);
            try
            {
                tokenPrivileges = (Winnt._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(hTokenPrivileges, typeof(Winnt._TOKEN_PRIVILEGES_ARRAY));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenPrivileges);
            }

            Console.WriteLine("[+] Enumerated {0} Privileges", tokenPrivileges.PrivilegeCount);
            Console.WriteLine();
            Console.WriteLine("{0,-45}{1,-30}", "Privilege Name", "Enabled");
            Console.WriteLine("{0,-45}{1,-30}", "--------------", "-------");

            ////////////////////////////////////////////////////////////////////////////////
            // Iterate through the return privileges
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            IntPtr hLookupPrivilegeName = Generic.GetExportAddress(hadvapi32, "LookupPrivilegeNameW");
            MonkeyWorks.advapi32.LookupPrivilegeNameW fLookupPrivilegeName = (MonkeyWorks.advapi32.LookupPrivilegeNameW)Marshal.GetDelegateForFunctionPointer(hLookupPrivilegeName, typeof(MonkeyWorks.advapi32.LookupPrivilegeNameW));

            //IntPtr hPrivilegeCheck = Generic.GetExportAddress(hadvapi32, "PrivilegeCheck");
            //MonkeyWorks.advapi32.PrivilegeCheck fPrivilegeCheck = (MonkeyWorks.advapi32.PrivilegeCheck)Marshal.GetDelegateForFunctionPointer(hPrivilegeCheck, typeof(MonkeyWorks.advapi32.PrivilegeCheck));

            IntPtr hNtPrivilegeCheck = Generic.GetSyscallStub("NtPrivilegeCheck");
            MonkeyWorks.ntdll.NtPrivilegeCheck fSyscallNtPrivilegeCheck = (MonkeyWorks.ntdll.NtPrivilegeCheck)Marshal.GetDelegateForFunctionPointer(hNtPrivilegeCheck, typeof(MonkeyWorks.ntdll.NtPrivilegeCheck));


            for (int i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                uint cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                ////////////////////////////////////////////////////////////////////////////////
                // Lookup the name of of the privilege from the returned luid
                // Requires two passes to get the length of the strin
                // advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                // advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName)
                ////////////////////////////////////////////////////////////////////////////////
                
                try
                {
                    fLookupPrivilegeName(null, lpLuid, null, ref cchName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }

                if (cchName <= 0 || cchName > int.MaxValue)
                {
                    Misc.GetWin32Error("LookupPrivilegeName Pass 1");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                lpName.EnsureCapacity((int)cchName + 1);

                bool retVal = false;
                try
                {
                    retVal = fLookupPrivilegeName(null, lpLuid, lpName, ref cchName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }

                if (!retVal)
                {
                    Misc.GetWin32Error("LookupPrivilegeName Pass 2");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                ////////////////////////////////////////////////////////////////////////////////
                // Lookup if the privilege is enable
                // advapi32.PrivilegeCheck(hWorkingToken, ref privilegeSet, out pfResult)
                ////////////////////////////////////////////////////////////////////////////////
                
                int pfResult = 0;
                Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };

                uint ntRetVal = 0;
                try
                {
                    ntRetVal = fSyscallNtPrivilegeCheck(hWorkingToken, ref privilegeSet, ref pfResult);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    continue;
                }
                finally
                {
                    Marshal.FreeHGlobal(lpLuid);
                }
                
                if (0 != ntRetVal)
                {
                    Misc.GetNtError("NtPrivilegeCheck", ntRetVal);
                    continue;
                }
                Console.WriteLine("{0,-45}{1,-30}", lpName.ToString(), Convert.ToBoolean(pfResult));
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Displays the users associated with a token
        /// P/Invokes moved to _GetTokenInformation 
        /// advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenOwner, IntPtr.Zero, 0, out returnLength);
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenOwner()
        {
            IntPtr hTokenOwner = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenOwner);
            try
            {
                tokenOwner = (Ntifs._TOKEN_OWNER)Marshal.PtrToStructure(hTokenOwner, typeof(Ntifs._TOKEN_OWNER));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenOwner);
            }

            Console.WriteLine("[+] Owner: ");
            string sid, account;
            _ReadSidAndName(tokenOwner.Owner, out sid, out account);
            Console.WriteLine("{0,-50} {1}", sid, account);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Displays the users associated with a token
        /// P/Invokes moved to _GetTokenInformation 
        /// advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, IntPtr.Zero, 0, out returnLength);
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenPrimaryGroup()
        {
            IntPtr hTokenPrimaryGroup = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenPrimaryGroup);
            try
            {
                tokenPrimaryGroup = (Winnt._TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(hTokenPrimaryGroup, typeof(Winnt._TOKEN_PRIMARY_GROUP));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenPrimaryGroup);
            }

            string primaryGroupSid, primaryGroupName;
            _ReadSidAndName(tokenPrimaryGroup.PrimaryGroup, out primaryGroupSid, out primaryGroupName);
            Console.WriteLine("[+] Primary Group: ");
            Console.WriteLine("{0,-50} {1}", primaryGroupSid, primaryGroupName);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Displays the users associated with a token
        /// P/Invokes moved to _GetTokenInformation 
        /// advapi32.GetTokenInformation(hWorkingToken, Winnt._TOKEN_INFORMATION_CLASS.TokenDefaultDacl, hTokenDefaultDacl, returnLength, out returnLength);
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetTokenDefaultDacl()
        {
            IntPtr hTokenDefaultDacl = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenDefaultDacl);
            try
            {
                tokenDefaultDacl = (Winnt._TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(hTokenDefaultDacl, typeof(Winnt._TOKEN_DEFAULT_DACL));
                if (IntPtr.Zero == tokenDefaultDacl.DefaultDacl)
                {
                    Misc.GetWin32Error("PtrToStructure");
                }
                tokenDefaultDaclAcl = (Winnt._TOKEN_DEFAULT_DACL_ACL)Marshal.PtrToStructure(hTokenDefaultDacl, typeof(Winnt._TOKEN_DEFAULT_DACL_ACL));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(hTokenDefaultDacl);
            }

            string primaryGroup = Marshal.PtrToStringUni(tokenPrimaryGroup.PrimaryGroup);
            Console.WriteLine("[+] ACL Count: {0}", tokenDefaultDaclAcl.DefaultDacl.AceCount);
            return;
        }
        #endregion

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pointer"></param>
        /// <param name="sid"></param>
        /// <param name="account"></param>
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
        /// <summary>
        /// Helper function for GetTokenInformation
        /// Converted all GetTokenInformation calls to D/Invoke Syscall
        /// </summary>
        /// <param name="tokenInformationClass"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private IntPtr _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS tokenInformationClass)
        {
            IntPtr hNtQueryInformationToken = Generic.GetSyscallStub("NtQueryInformationToken");
            MonkeyWorks.ntdll.NtQueryInformationToken fSyscallNtQueryInformationToken = (MonkeyWorks.ntdll.NtQueryInformationToken)Marshal.GetDelegateForFunctionPointer(hNtQueryInformationToken, typeof(MonkeyWorks.ntdll.NtQueryInformationToken));

            IntPtr tokenInformation = IntPtr.Zero;
            try
            {
                ulong returnLength = 0;
                fSyscallNtQueryInformationToken(hWorkingToken, tokenInformationClass, tokenInformation, returnLength, ref returnLength);
                tokenInformation = Marshal.AllocHGlobal((int)returnLength);

                uint ntRetVal = fSyscallNtQueryInformationToken(hWorkingToken, tokenInformationClass, tokenInformation, returnLength, ref returnLength);
                if (0 != ntRetVal)
                {
                    Misc.GetNtError("NtQueryInformationToken", ntRetVal);
                    return IntPtr.Zero;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtDuplicateToken Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return IntPtr.Zero;
            }

            return tokenInformation;
        }
    }
}