using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

using Tokenvator.Plugins.AccessTokens;
using Tokenvator.Resources;

namespace Tokenvator.Plugins.Enumeration
{
    class DesktopACL : IDisposable
    {
        private const uint SECURITY_MAX_SID_SIZE = 68;

        private IntPtr ptrWinSta0 = IntPtr.Zero;
        private IntPtr pSid = IntPtr.Zero;
        private IntPtr ppSecurityDescriptor = IntPtr.Zero;

        private IntPtr hToken;

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Default Constructor
        /// No Conversions Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        internal DesktopACL(IntPtr hToken)
        {
            Console.WriteLine("[*] Updating Desktop DACL");
            ptrWinSta0 = Marshal.StringToHGlobalUni("WinSta0");
            this.hToken = hToken;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Opens a handle to the window station
        /// 
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        internal void OpenWindow()
        {
            using (TokenInformation ti = new TokenInformation(hToken))
            {
                ti.SetWorkingTokenToSelf();
                if (!ti.CheckTokenPrivilege(Winnt.SE_SECURITY_NAME))
                {
                    Console.WriteLine("[-] {0} is not present on the token", Winnt.SE_SECURITY_NAME);
                    return;
                }
                else
                {
                    Console.WriteLine("[+] {0} is present and enabled on the token", Winnt.SE_SECURITY_NAME);
                }
            }

            IntPtr hWinStation = user32.OpenWindowStationW(
                ptrWinSta0, 
                false,
                Winuser.WindowStationSecurity.ACCESS_SYSTEM_SECURITY
                | Winuser.WindowStationSecurity.READ_CONTROL
                | Winuser.WindowStationSecurity.WRITE_DAC
            );

            if (IntPtr.Zero == hWinStation)
            {
                Misc.GetWin32Error("OpenWindowStationW");
                return;
            }
            Console.WriteLine("[+] hWinSta0 : 0x{0}", hWinStation.ToString("X4"));

            _SetDACL(hWinStation);
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Opens a handle to the desktop
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        internal void OpenDesktop()
        {
            IntPtr hDesktop = user32.OpenDesktopA(
                "default", 0, false, 
                Winuser.DesktopSecurity.GENERIC_ALL 
                | Winuser.DesktopSecurity.WRITE_DAC);

            if (IntPtr.Zero == hDesktop)
            {
                Misc.GetWin32Error("OpenDesktopW");
                return;
            }
            Console.WriteLine("[+] hDesktop : 0x{0}", hDesktop.ToString("X4"));

            _SetDACL(hDesktop);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="handle"></param>
        private void _SetDACL(IntPtr handle)
        {
            ////////////////////////////////////////////////////////////////////////////////
            //
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr ppsidOwner, ppsidGroup, ppDacl, ppSacl;
            ppsidOwner = ppsidGroup = ppDacl = ppSacl = IntPtr.Zero;
            uint status = advapi32.GetSecurityInfo(
                handle,
                Accctrl._SE_OBJECT_TYPE.SE_WINDOW_OBJECT,
                Winnt.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                ref ppsidOwner, ref ppsidGroup, ref ppDacl, ref ppSacl, ref ppSecurityDescriptor
            );

            if (0 != status)
            {
                Console.WriteLine(status);
                Misc.GetWin32Error("GetSecurityInfo");
                return;
            }
            
            if (IntPtr.Zero == ppDacl)
            {
                Misc.GetWin32Error("ppDacl");
                return;
            }
            Console.WriteLine(" [+] Recieved DACL : 0x{0}", ppDacl.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            // 
            ////////////////////////////////////////////////////////////////////////////////
            uint size = 0;
            advapi32.CreateWellKnownSid(Winnt.WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, IntPtr.Zero, ref size);
            if (0 == size)
            {
                Misc.GetWin32Error("CreateWellKnownSid - Pass 1");
                return;
            }
            Console.WriteLine(" [+] Create Everyone Sid - Pass 1 : 0x{0}", size.ToString("X4"));
            pSid = Marshal.AllocHGlobal((int)size);

            if (!advapi32.CreateWellKnownSid(Winnt.WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, pSid, ref size))
            {
                Misc.GetWin32Error("CreateWellKnownSid - Pass 2");
                return;
            }
            Console.WriteLine(" [+] Create Everyone Sid - Pass 2 : 0x{0}", pSid.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            Accctrl._TRUSTEE_A trustee = new Accctrl._TRUSTEE_A
            {
                pMultipleTrustee = IntPtr.Zero,
                MultipleTrusteeOperation = Accctrl._MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
                TrusteeForm = Accctrl._TRUSTEE_FORM.TRUSTEE_IS_SID,
                TrusteeType = Accctrl._TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName = pSid
            };

            Accctrl._EXPLICIT_ACCESS_A explicitAccess = new Accctrl._EXPLICIT_ACCESS_A
            {
                grfAccessPermissions = 0xf03ff,
                grfAccessMode = Accctrl._ACCESS_MODE.GRANT_ACCESS,
                grfInheritance = 1,
                Trustee = trustee
            };

            IntPtr newAcl = new IntPtr();
            status = advapi32.SetEntriesInAclA(1, ref explicitAccess, ppDacl, ref newAcl);

            if (0 != status)
            {
                Console.WriteLine(status);
                Misc.GetWin32Error("SetEntriesInAclW");
                return;
            }
           
            if (IntPtr.Zero == newAcl)
            {
                Misc.GetWin32Error("newAcl");
                return;
            }
            Console.WriteLine(" [+] Added Everyone to DACL : 0x{0}", newAcl.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            status = advapi32.SetSecurityInfo(
                handle,
                Accctrl._SE_OBJECT_TYPE.SE_WINDOW_OBJECT,
                Winnt.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                ppsidOwner, ppsidGroup, newAcl, ppSacl
            );

            if (0 != status)
            {
                Console.WriteLine(status);
                Misc.GetWin32Error("SetSecurityInfo");
                return;
            }
            Console.WriteLine(" [+] Applied DACL to Object");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hToken"></param>
        internal void UpdateSecurityDacl(IntPtr hToken)
        {
            TokenInformation tokenInformation = new TokenInformation(hToken);
            tokenInformation.GetTokenUser();

            #region Windows Station
            IntPtr hWindowStation = user32.GetProcessWindowStation();
            if (IntPtr.Zero == hWindowStation)
            {
                Misc.GetWin32Error("GetProcessWindowStation");
                return;
            }

            Winnt.SECURITY_INFORMATION pSIRequested = Winnt.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
            //Winnt._SECURITY_DESCRIPTOR pSID = new Winnt._SECURITY_DESCRIPTOR();
            uint nLength = 0;

            user32.GetUserObjectSecurity(hWindowStation, ref pSIRequested, IntPtr.Zero, nLength, ref nLength);
            IntPtr pSID = Marshal.AllocHGlobal((int)nLength);
            if (!user32.GetUserObjectSecurity(hWindowStation, ref pSIRequested, pSID, nLength, ref nLength))
            {
                Misc.GetWin32Error("GetUserObjectSecurity");
                return;
            }

            bool bDaclPresent = false;
            Winnt._ACL oldACL = new Winnt._ACL();
            bool bDaclDefaulted = false;
            if (!advapi32.GetSecurityDescriptorDacl(pSID, ref bDaclPresent, ref oldACL, ref bDaclDefaulted))
            {
                Misc.GetWin32Error("GetSecurityDescriptorDacl");
                return;
            }

            if (!bDaclPresent)
            {
                Console.WriteLine("[-] DACL not present, attempt a different method");
                return;
            }

            Accctrl._TRUSTEE_W trustee = new Accctrl._TRUSTEE_W()
            {
                pMultipleTrustee = IntPtr.Zero,
                MultipleTrusteeOperation = Accctrl._MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
                TrusteeForm = Accctrl._TRUSTEE_FORM.TRUSTEE_IS_SID,
                TrusteeType = Accctrl._TRUSTEE_TYPE.TRUSTEE_IS_USER,
                ptstrName = tokenInformation.tokenUser.User.Sid
            };

            Accctrl._EXPLICIT_ACCESS_W explicitAccess = new Accctrl._EXPLICIT_ACCESS_W()
            {
                grfAccessMode = Accctrl._ACCESS_MODE.SET_ACCESS,
                grfAccessPermissions = Winuser.WindowStationSecurity.WINSTA_ALL_ACCESS | Winuser.WindowStationSecurity.READ_CONTROL,
                grfInheritance = Accctrl.Inheritance.NO_INHERITANCE,
                Trustee = trustee
            };

            Winnt._ACL newACL = new Winnt._ACL();
            uint retVal = advapi32.SetEntriesInAclW(1, ref explicitAccess, ref oldACL, ref newACL);
            if (0 != retVal)
            {
                Misc.GetWin32Error("SetEntriesInAclW");
                return;
            }

            Winnt._SECURITY_DESCRIPTOR securityDescriptor = new Winnt._SECURITY_DESCRIPTOR();
            if (!advapi32.InitializeSecurityDescriptor(securityDescriptor, 1))
            {
                Misc.GetWin32Error("InitializeSecurityDescriptor");
                return;
            }

            if (!advapi32.SetSecurityDescriptorDacl(ref securityDescriptor, true, ref newACL, false))
            {
                Misc.GetWin32Error("SetSecurityDescriptorDacl");
                return;
            }

            if (!user32.SetUserObjectSecurity(hWindowStation, pSIRequested, securityDescriptor))
            {
                Misc.GetWin32Error("SetUserObjectSecurity");
                return;
            }
            #endregion


        }

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            if (IntPtr.Zero != ptrWinSta0)
                Marshal.FreeHGlobal(ptrWinSta0);

            if (IntPtr.Zero != pSid)
                Marshal.FreeHGlobal(pSid);

            if (IntPtr.Zero != ppSecurityDescriptor)
                kernel32.LocalFree(ppSecurityDescriptor);
        }

        /// <summary>
        /// 
        /// </summary>
        ~DesktopACL()
        {
            Dispose();
        }
    }
}
