using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;

using DInvoke.DynamicInvoke;

using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

using Tokenvator.Plugins.AccessTokens;
using Tokenvator.Resources;

namespace Tokenvator.Plugins.Enumeration
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    sealed class DesktopACL : IDisposable
    {
        private bool disposed = false;

        private IntPtr ptrWinSta0 = IntPtr.Zero;
        private IntPtr pSid = IntPtr.Zero;
        private IntPtr ppSecurityDescriptor = IntPtr.Zero;

        private IntPtr hToken;

        private IntPtr huser32 = IntPtr.Zero;
        private IntPtr hadvapi32 = IntPtr.Zero;

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
        /// Default destructor, calls Disposed if not previously disposed
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        ~DesktopACL()
        {
            if (!disposed)
            {
                Dispose();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// IDisposable close handles
        /// Converted to D/Invoke GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            if (IntPtr.Zero != ptrWinSta0)
            {
                Marshal.FreeHGlobal(ptrWinSta0);
            }

            if (IntPtr.Zero != pSid)
            {
                Marshal.FreeHGlobal(pSid);
            }

            if (IntPtr.Zero != ppSecurityDescriptor)
            {
                IntPtr hkernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
                IntPtr hLocalFree = Generic.GetExportAddress(hkernel32, "LocalFree");
                MonkeyWorks.kernel32.LocalFree fLocalFree = (MonkeyWorks.kernel32.LocalFree)Marshal.GetDelegateForFunctionPointer(hLocalFree, typeof(MonkeyWorks.kernel32.LocalFree));
                try
                {
                    fLocalFree(ppSecurityDescriptor);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] LocalFree Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                }
            }

            disposed = true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Loads the user32.dll Libary
        /// huser32 = kernel32.LoadLibrary("user32.dll");
        /// Converted to D/Invoke GetPebLdrModuleEntry/LoadModuleFromDisk
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        internal bool LoadModule()
        {
            huser32 = Generic.GetPebLdrModuleEntry("user32.dll");
            if (IntPtr.Zero == huser32)
            {
                huser32 = Generic.LoadModuleFromDisk("user32.dll");
                if (IntPtr.Zero == huser32)
                {
                    Console.WriteLine("Unable to load user32.dll");
                    return false;
                }
            }

            hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Opens a handle to the window station
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal bool OpenWindow()
        {
            using (TokenInformation ti = new TokenInformation(hToken))
            {
                ti.SetWorkingTokenToSelf();
                if (!ti.CheckTokenPrivilege(Winnt.SE_SECURITY_NAME))
                {
                    Console.WriteLine("[-] {0} is not present on the token", Winnt.SE_SECURITY_NAME);
                    return false;
                }
                else
                {
                    Console.WriteLine("[+] {0} is present and enabled on the token", Winnt.SE_SECURITY_NAME);
                }
            }

            ////////////////////////////////////////////////////////////////////////////////
            // IntPtr hWinStation = user32.OpenWindowStationW("ptrWinSta0", false, Winuser.WindowStationSecurity.ACCESS_SYSTEM_SECURITY | Winuser.WindowStationSecurity.READ_CONTROL | Winuser.WindowStationSecurity.WRITE_DAC);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hOpenWindowStationW = Generic.GetExportAddress(huser32, "OpenWindowStationW");
            MonkeyWorks.user32.OpenWindowStationW fOpenWindowStationW = (MonkeyWorks.user32.OpenWindowStationW)Marshal.GetDelegateForFunctionPointer(hOpenWindowStationW, typeof(MonkeyWorks.user32.OpenWindowStationW));

            IntPtr hWinStation;

            try
            {
                hWinStation = fOpenWindowStationW(
                    ptrWinSta0,
                    false,
                    Winuser.WindowStationSecurity.ACCESS_SYSTEM_SECURITY
                    | Winuser.WindowStationSecurity.READ_CONTROL
                    | Winuser.WindowStationSecurity.WRITE_DAC
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] OpenWindowStationW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (IntPtr.Zero == hWinStation)
            {
                Misc.GetWin32Error("OpenWindowStationW");
                return false;
            }
            Console.WriteLine("[+] hWinSta0 : 0x{0}", hWinStation.ToString("X4"));

            _SetDACL(hWinStation);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Opens a handle to the desktop
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        internal bool OpenDesktop()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // IntPtr hWinStation = user32.OpenWindowStationW("ptrWinSta0", false, Winuser.WindowStationSecurity.ACCESS_SYSTEM_SECURITY | Winuser.WindowStationSecurity.READ_CONTROL | Winuser.WindowStationSecurity.WRITE_DAC);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hOpenDesktopW = Generic.GetExportAddress(huser32, "OpenDesktopW");
            MonkeyWorks.user32.OpenDesktopW fOpenDesktopW = (MonkeyWorks.user32.OpenDesktopW)Marshal.GetDelegateForFunctionPointer(hOpenDesktopW, typeof(MonkeyWorks.user32.OpenDesktopW));

            IntPtr hDesktop;
            try
            {
                hDesktop = fOpenDesktopW(
                    "default", 0, false,
                    Winuser.DesktopSecurity.GENERIC_ALL
                    | Winuser.DesktopSecurity.WRITE_DAC
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] OpenDesktopW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (IntPtr.Zero == hDesktop)
            {
                Misc.GetWin32Error("OpenDesktopW");
                return false;
            }
            Console.WriteLine("[+] hDesktop : 0x{0}", hDesktop.ToString("X4"));

            _SetDACL(hDesktop);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Updates the DACL on the object passed in to Everyone
        /// Converted to D/Invoke GetExportAddress
        /// </summary>
        /// <returns></returns>
        /// <param name="handle"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private bool _SetDACL(IntPtr handle)
        {
            ////////////////////////////////////////////////////////////////////////////////
            //advapi32.GetSecurityInfo(handle, Accctrl._SE_OBJECT_TYPE.SE_WINDOW_OBJECT, Winnt.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, ref ppsidOwner, ref ppsidGroup, ref ppDacl, ref ppSacl, ref ppSecurityDescriptor);
            ////////////////////////////////////////////////////////////////////////////////
            #region GetSecurityInfo
            IntPtr hGetSecurityInfo = Generic.GetExportAddress(hadvapi32, "GetSecurityInfo");
            MonkeyWorks.advapi32.GetSecurityInfo fGetSecurityInfo = (MonkeyWorks.advapi32.GetSecurityInfo)Marshal.GetDelegateForFunctionPointer(hGetSecurityInfo, typeof(MonkeyWorks.advapi32.GetSecurityInfo));

            IntPtr ppsidOwner, ppsidGroup, ppDacl, ppSacl;
            ppsidOwner = ppsidGroup = ppDacl = ppSacl = IntPtr.Zero;

            uint status;
            try
            { 
                status = fGetSecurityInfo(
                    handle,
                    Accctrl._SE_OBJECT_TYPE.SE_WINDOW_OBJECT,
                    Winnt.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                    ref ppsidOwner, ref ppsidGroup, ref ppDacl, ref ppSacl, ref ppSecurityDescriptor
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] GetSecurityInfo Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != status)
            {
                Console.WriteLine(status);
                Misc.GetWin32Error("GetSecurityInfo");
                return false;
            }
            
            if (IntPtr.Zero == ppDacl)
            {
                Misc.GetWin32Error("ppDacl");
                return false;
            }

            Console.WriteLine(" [+] Recieved DACL : 0x{0}", ppDacl.ToString("X4"));
            #endregion

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.CreateWellKnownSid(Winnt.WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, IntPtr.Zero, ref size);
            // advapi32.CreateWellKnownSid(Winnt.WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, pSid, ref size)
            ////////////////////////////////////////////////////////////////////////////////
            #region CreateWellKnownSid
            IntPtr hCreateWellKnownSid = Generic.GetExportAddress(hadvapi32, "CreateWellKnownSid");
            MonkeyWorks.advapi32.CreateWellKnownSid fCreateWellKnownSid = (MonkeyWorks.advapi32.CreateWellKnownSid)Marshal.GetDelegateForFunctionPointer(hCreateWellKnownSid, typeof(MonkeyWorks.advapi32.CreateWellKnownSid));

            uint size = 0;
            try
            { 
                fCreateWellKnownSid(Winnt.WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, IntPtr.Zero, ref size);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CreateWellKnownSid Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 == size)
            {
                Misc.GetWin32Error("CreateWellKnownSid - Pass 1");
                return false;
            }
            Console.WriteLine(" [+] Create Everyone Sid - Pass 1 : 0x{0}", size.ToString("X4"));
            pSid = Marshal.AllocHGlobal((int)size);

            bool retVal = false;
            try
            {
                retVal = fCreateWellKnownSid(Winnt.WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, pSid, ref size);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CreateWellKnownSid Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (!retVal)
            {
                Misc.GetWin32Error("CreateWellKnownSid - Pass 2");
                return false;
            }
            Console.WriteLine(" [+] Create Everyone Sid - Pass 2 : 0x{0}", pSid.ToString("X4"));
            #endregion

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.SetEntriesInAclW(1, ref explicitAccess, ppDacl, ref newAcl);
            ////////////////////////////////////////////////////////////////////////////////
            #region SetEntriesInAclW
            IntPtr hSetEntriesInAclW = Generic.GetExportAddress(hadvapi32, "SetEntriesInAclW");
            MonkeyWorks.advapi32.SetEntriesInAclW fSetEntriesInAclW = (MonkeyWorks.advapi32.SetEntriesInAclW)Marshal.GetDelegateForFunctionPointer(hSetEntriesInAclW, typeof(MonkeyWorks.advapi32.SetEntriesInAclW));

            Accctrl._TRUSTEE_W trustee = new Accctrl._TRUSTEE_W
            {
                pMultipleTrustee = IntPtr.Zero,
                MultipleTrusteeOperation = Accctrl._MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
                TrusteeForm = Accctrl._TRUSTEE_FORM.TRUSTEE_IS_SID,
                TrusteeType = Accctrl._TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName = pSid
            };

            Accctrl._EXPLICIT_ACCESS_W explicitAccess = new Accctrl._EXPLICIT_ACCESS_W
            {
                grfAccessPermissions = Winuser.WindowStationSecurity.WINSTA_ALL_ACCESS,//0xf03ff,
                grfAccessMode = Accctrl._ACCESS_MODE.GRANT_ACCESS,
                grfInheritance = Accctrl.Inheritance.SUB_OBJECTS_ONLY_INHERIT, // 1,
                Trustee = trustee
            };

            IntPtr newAcl = new IntPtr();

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSetEntriesInAclW(1, ref explicitAccess, ppDacl, ref newAcl);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] SetEntriesInAclW Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }

            if (0 != status)
            {
                Console.WriteLine(status);
                Misc.GetWin32Error("SetEntriesInAclW");
                return false;
            }
           
            if (IntPtr.Zero == newAcl)
            {
                Misc.GetWin32Error("newAcl");
                return false;
            }
            Console.WriteLine(" [+] Added Everyone to DACL : 0x{0}", newAcl.ToString("X4"));
            #endregion

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.SetSecurityInfo(handle, Accctrl._SE_OBJECT_TYPE.SE_WINDOW_OBJECT, Winnt.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, ppsidOwner, ppsidGroup, newAcl, ppSacl);
            ////////////////////////////////////////////////////////////////////////////////
            #region SetEntriesInAclW
            IntPtr hSetSecurityInfo = Generic.GetExportAddress(hadvapi32, "SetSecurityInfo");
            MonkeyWorks.advapi32.SetSecurityInfo fSetSecurityInfo = (MonkeyWorks.advapi32.SetSecurityInfo)Marshal.GetDelegateForFunctionPointer(hSetSecurityInfo, typeof(MonkeyWorks.advapi32.SetSecurityInfo));

            status = 0;
            try
            {
                status = fSetSecurityInfo(
                    handle,
                    Accctrl._SE_OBJECT_TYPE.SE_WINDOW_OBJECT,
                    Winnt.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                    ppsidOwner, ppsidGroup, newAcl, ppSacl
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] SetSecurityInfo Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
           
            if (0 != status)
            {
                Console.WriteLine(status);
                Misc.GetWin32Error("SetSecurityInfo");
                return false;
            }
            Console.WriteLine(" [+] Applied DACL to Object");
            #endregion

            return true;
        }

        /*
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

            IntPtr lpOldACL = Marshal.AllocHGlobal(Marshal.SizeOf(oldACL));
            Marshal.StructureToPtr(oldACL, lpOldACL, false);

            Winnt._ACL newACL = new Winnt._ACL();
            IntPtr lpNewAcl = Marshal.AllocHGlobal(Marshal.SizeOf(newACL));
            Marshal.StructureToPtr(newACL, lpNewAcl, false);

            uint retVal = advapi32.SetEntriesInAclW(1, ref explicitAccess, lpOldACL, ref lpNewAcl);
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
        */
    }
}
