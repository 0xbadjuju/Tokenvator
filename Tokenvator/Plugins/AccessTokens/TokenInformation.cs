using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

using DInvoke.DynamicInvoke;

using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;

//using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    class TokenInformation : AccessTokens
    {
        public bool tiDisposed = false;

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
        public IntPtr hTokenElevationType;
        public IntPtr hTokenType;

        public List<string> Privileges { get; private set; }

        private readonly IntPtr hNtQueryInformationToken;
        private readonly IntPtr hadvapi32;

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default Constructor
        /// </summary>
        /// <param name="hToken"></param>
        ////////////////////////////////////////////////////////////////////////////////
        public TokenInformation(IntPtr hToken) : base(hToken)
        {
            hNtQueryInformationToken = Generic.GetSyscallStub("NtQueryInformationToken");
            hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            Privileges = new List<string>();
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
        public override void Dispose()
        {
            tiDisposed = true;

            if (IntPtr.Zero != hTokenSource)
            {
                //Marshal.FreeHGlobal(hTokenSource);
            }
            if (IntPtr.Zero != hTokenUser)
            {
                //Marshal.FreeHGlobal(hTokenUser);
            }
            if (IntPtr.Zero != hTokenGroups)
            {
                //Marshal.FreeHGlobal(hTokenGroups);
            }
            if (IntPtr.Zero != hTokenPrivileges)
            {
                //Marshal.FreeHGlobal(hTokenPrivileges);
            }
            if (IntPtr.Zero != hTokenOwner)
            {
                //Marshal.FreeHGlobal(hTokenOwner);
            }
            if (IntPtr.Zero != hTokenPrimaryGroup)
            {
                //Marshal.FreeHGlobal(hTokenPrimaryGroup);
            }
            if (IntPtr.Zero != hTokenDefaultDacl)
            {
                //Marshal.FreeHGlobal(hTokenDefaultDacl);
            }
            if (IntPtr.Zero != hTokenElevationType)
            {
                //Marshal.FreeHGlobal(hTokenElevationType);
            }
            if (IntPtr.Zero != hTokenType)
            {
                //Marshal.FreeHGlobal(hTokenType);
            }

            base.Dispose();
        }

        #region ThreadInformation
        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Lists the users for threads
        /// No Conversions Required 
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void GetThreadUsers(bool showOutput = true)
        {
            foreach (uint t in threads)
            {
                if (showOutput)
                {
                    Console.WriteLine("[*] Thread ID: " + t);
                }

                if (OpenThreadToken(t, Winnt.TOKEN_QUERY, showOutput))
                {
                    SetWorkingTokenToThreadToken();
                    string user = GetTokenUser(showOutput);

                    if (!showOutput)
                    {
                        Console.WriteLine("[*] Thread: {0} - {1}", t, user);
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
            hTokenElevationType = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenElevationType);
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
            hTokenType = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenType);
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
            hTokenSource = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenSource);
            try
            {
                tokenSource = (Winnt._TOKEN_SOURCE)Marshal.PtrToStructure(hTokenSource, typeof(Winnt._TOKEN_SOURCE));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return;
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
        public string GetTokenUser(bool showOutput = true)
        {
            hTokenUser = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenUser);
            try
            {
                tokenUser = (Ntifs._TOKEN_USER)Marshal.PtrToStructure(hTokenUser, typeof(Ntifs._TOKEN_USER));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return string.Empty;
            }

            if (showOutput)
            {
                Console.WriteLine("[+] User: ");
            }
            string sid, account;
            ReadSidAndName(tokenUser.User.Sid, out sid, out account);
            if (showOutput)
            {
                Console.WriteLine("{0,-50} {1}", sid, account);
            }
            return account;
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
            hTokenGroups = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenGroups);
            try
            {
                tokenGroups = (Ntifs._TOKEN_GROUPS)Marshal.PtrToStructure(hTokenGroups, typeof(Ntifs._TOKEN_GROUPS));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }

            Console.WriteLine("[+] Enumerated {0} Groups: ", tokenGroups.GroupCount);
            for (int i = 0; i < tokenGroups.GroupCount; i++)
            {
                string sid, account;
                ReadSidAndName(tokenGroups.Groups[i].Sid, out sid, out account);
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
            hTokenPrivileges = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges);
            try
            {
                tokenPrivileges = (Winnt._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(hTokenPrivileges, typeof(Winnt._TOKEN_PRIVILEGES_ARRAY));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return;
            }

            Console.WriteLine("[+] Enumerated {0} Privileges", tokenPrivileges.PrivilegeCount);
            Console.WriteLine();
            Console.WriteLine("{0,-45}{1,-30}", "Privilege Name", "Enabled");
            Console.WriteLine("{0,-45}{1,-30}", "--------------", "-------");

            ////////////////////////////////////////////////////////////////////////////////
            // Iterate through the return privileges
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hLookupPrivilegeNameW = Generic.GetExportAddress(hadvapi32, "LookupPrivilegeNameW");
            MonkeyWorks.advapi32.LookupPrivilegeNameW fLookupPrivilegeNameW = (MonkeyWorks.advapi32.LookupPrivilegeNameW)Marshal.GetDelegateForFunctionPointer(hLookupPrivilegeNameW, typeof(MonkeyWorks.advapi32.LookupPrivilegeNameW));

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
                    fLookupPrivilegeNameW(null, lpLuid, null, ref cchName);
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
                    retVal = fLookupPrivilegeNameW(null, lpLuid, lpName, ref cchName);
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

                Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };
                bool pfResult = false;

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

                if (!Privileges.Contains(lpName.ToString()))
                {
                    Privileges.Add(lpName.ToString().Trim());
                }
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
            hTokenOwner = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenOwner);
            try
            {
                tokenOwner = (Ntifs._TOKEN_OWNER)Marshal.PtrToStructure(hTokenOwner, typeof(Ntifs._TOKEN_OWNER));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return;
            }

            Console.WriteLine("[+] Owner: ");
            string sid, account;
            ReadSidAndName(tokenOwner.Owner, out sid, out account);
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
            hTokenPrimaryGroup = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenPrimaryGroup);
            try
            {
                tokenPrimaryGroup = (Winnt._TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(hTokenPrimaryGroup, typeof(Winnt._TOKEN_PRIMARY_GROUP));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return;
            }

            string primaryGroupSid, primaryGroupName;
            ReadSidAndName(tokenPrimaryGroup.PrimaryGroup, out primaryGroupSid, out primaryGroupName);
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
            hTokenDefaultDacl = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenDefaultDacl);
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
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return;
            }

            string primaryGroup = Marshal.PtrToStringUni(tokenPrimaryGroup.PrimaryGroup);
            Console.WriteLine("[+] ACL Count: {0}", tokenDefaultDaclAcl.DefaultDacl.AceCount);
            return;
        }
        #endregion

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Converts a pointers to an SID and returns it in its string/sddl form
        /// advapi32.ConvertSidToStringSid(ref structSid, ref lpSid);
        /// </summary>
        /// <param name="pointer"></param>
        /// <param name="sid"></param>
        /// <param name="account"></param>
        ////////////////////////////////////////////////////////////////////////////////
        public void ReadSidAndName(IntPtr pointer, out string sid, out string account)
        {
            IntPtr hConvertSidToStringSidW = Generic.GetExportAddress(hadvapi32, "ConvertSidToStringSidW");
            MonkeyWorks.advapi32.ConvertSidToStringSidW fConvertSidToStringSidW = (MonkeyWorks.advapi32.ConvertSidToStringSidW)Marshal.GetDelegateForFunctionPointer(hConvertSidToStringSidW, typeof(MonkeyWorks.advapi32.ConvertSidToStringSidW));

            sid = string.Empty;
            account = string.Empty;
            IntPtr lpSid = IntPtr.Zero;
            try
            {
                Ntifs._SID structSid = (Ntifs._SID)Marshal.PtrToStructure(pointer, typeof(Ntifs._SID));

                bool retVal = fConvertSidToStringSidW(ref structSid, ref lpSid);
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
                Marshal.FreeHGlobal(lpSid);
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
        /// <summary>
        /// Checks if a Privilege Exists and is Enabled
        /// Converted to a mix of D/Invoke Syscalls and GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="privilegeName"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool CheckTokenPrivilege(string privilegeName)
        {
            bool exists = false;
            bool enabled = false;

            IntPtr lpTokenInformation = _GetTokenInformation(Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges);

            if (IntPtr.Zero == lpTokenInformation)
            {
                return false;
            }

            Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges;
            try
            {
                tokenPrivileges = (Winnt._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(Winnt._TOKEN_PRIVILEGES_ARRAY));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] PtrToStructure Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }

            IntPtr hLookupPrivilegeName = Generic.GetExportAddress(hadvapi32, "LookupPrivilegeNameW");
            MonkeyWorks.advapi32.LookupPrivilegeNameW fLookupPrivilegeName = (MonkeyWorks.advapi32.LookupPrivilegeNameW)Marshal.GetDelegateForFunctionPointer(hLookupPrivilegeName, typeof(MonkeyWorks.advapi32.LookupPrivilegeNameW));

            IntPtr hNtPrivilegeCheck = Generic.GetSyscallStub("NtPrivilegeCheck");
            MonkeyWorks.ntdll.NtPrivilegeCheck fSyscallNtPrivilegeCheck = (MonkeyWorks.ntdll.NtPrivilegeCheck)Marshal.GetDelegateForFunctionPointer(hNtPrivilegeCheck, typeof(MonkeyWorks.ntdll.NtPrivilegeCheck));

            ////////////////////////////////////////////////////////////////////////////////
            // Iterate through each returned privilege to check if it both exists and is enabled
            ////////////////////////////////////////////////////////////////////////////////
            for (int i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                ////////////////////////////////////////////////////////////////////////////////
                // Lookup the privilege name based upon the luid returned by GetTokenInformation
                // advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                // advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName);
                ////////////////////////////////////////////////////////////////////////////////

                StringBuilder lpName = new StringBuilder();
                uint cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                fLookupPrivilegeName(null, lpLuid, null, ref cchName);
                if (cchName <= 0 || cchName > int.MaxValue)
                {
                    Misc.GetWin32Error("LookupPrivilegeName Pass 1");
                    continue;
                }

                lpName.EnsureCapacity((int)cchName + 1);
                if (!fLookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                {
                    Misc.GetWin32Error("LookupPrivilegeName Pass 2");
                    continue;
                }

                if (lpName.ToString() != privilegeName)
                {
                    continue;
                }
                exists = true;

                ////////////////////////////////////////////////////////////////////////////////
                // Check if the privilege is also enabled on the token
                // advapi32.PrivilegeCheck(hToken, ref privilegeSet, out pfResult);
                ////////////////////////////////////////////////////////////////////////////////

                Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };
                bool pfResult = false;

                uint ntRetVal = fSyscallNtPrivilegeCheck(hWorkingToken, ref privilegeSet, ref pfResult);

                if (0 != ntRetVal)
                {
                    Misc.GetNtError("PrivilegeCheck", ntRetVal);
                    continue;
                }
                enabled = Convert.ToBoolean(pfResult);
                break;
            }

            if (!exists)
            {
                Console.WriteLine("[-] Privileges {0} does not exist on the token");
                return false;
            }

            if (!enabled)
            {
                using(TokenManipulation tm = new TokenManipulation(hWorkingToken))
                {
                    tm.SetWorkingTokenToSelf();
                    if (!tm.SetTokenPrivilege(privilegeName, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED))
                    {
                        Console.WriteLine("[-] Unable to enable privilege {0}");
                        return false;
                    }
                }
            }

            Console.WriteLine();
            return true;
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
            var fSyscallNtQueryInformationToken = (MonkeyWorks.ntdll.NtQueryInformationToken)Marshal.GetDelegateForFunctionPointer(hNtQueryInformationToken, typeof(MonkeyWorks.ntdll.NtQueryInformationToken));

            IntPtr tokenInformation = IntPtr.Zero;
            ulong returnLength = 0;
            try
            {
                fSyscallNtQueryInformationToken(hWorkingToken, tokenInformationClass, tokenInformation, returnLength, ref returnLength);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtQueryInformationToken");
                return IntPtr.Zero;
            }
            tokenInformation = Marshal.AllocHGlobal((int)returnLength);

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtQueryInformationToken(hWorkingToken, tokenInformationClass, tokenInformation, returnLength, ref returnLength);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtQueryInformationToken");
                return IntPtr.Zero;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtQueryInformationToken", ntRetVal);
                return IntPtr.Zero;
            }

            return tokenInformation;
        }
    }
}