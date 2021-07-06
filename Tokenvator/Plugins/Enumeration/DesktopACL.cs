using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

using Tokenvator.Plugins.AccessTokens;
using Tokenvator.Resources;

namespace Tokenvator.Plugins.Enumeration
{
    class DesktopACL : IDisposable
    {
        #region P/Invokes
        [Flags]
        public enum WindowStationSecurity
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            SYNCHRONIZE = 0x00100000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,

            WINSTA_ALL_ACCESS = 0x37F,
            WINSTA_ACCESSCLIPBOARD = 0x0004,
            WINSTA_ACCESSGLOBALATOMS = 0x0020,
            WINSTA_CREATEDESKTOP = 0x0008,
            WINSTA_ENUMDESKTOPS = 0x0001,
            WINSTA_ENUMERATE = 0x0100,
            WINSTA_EXITWINDOWS = 0x0040,
            WINSTA_READATTRIBUTES = 0x0002,
            WINSTA_READSCREEN = 0x0200,
            WINSTA_WRITEATTRIBUTES = 0x0010,

            ACCESS_SYSTEM_SECURITY = 0x01000000
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenWindowStationW(
            IntPtr lpszWinSta,
            bool fInherit,
            WindowStationSecurity dwDesiredAccess
        );

        [Flags]
        public enum _SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY,
            SE_REGISTRY_WOW64_64KEY
        }

        [Flags]
        public enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000,
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint GetSecurityInfo(
            IntPtr handle,
            _SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            ref IntPtr ppsidOwner,
            ref IntPtr ppsidGroup,
            ref IntPtr ppDacl,
            ref IntPtr ppSacl,
            ref IntPtr ppSecurityDescriptor
        );

        [Flags]
        public enum WELL_KNOWN_SID_TYPE
        {
            WinNullSid,
            WinWorldSid,
            WinLocalSid,
            WinCreatorOwnerSid,
            WinCreatorGroupSid,
            WinCreatorOwnerServerSid,
            WinCreatorGroupServerSid,
            WinNtAuthoritySid,
            WinDialupSid,
            WinNetworkSid,
            WinBatchSid,
            WinInteractiveSid,
            WinServiceSid,
            WinAnonymousSid,
            WinProxySid,
            WinEnterpriseControllersSid,
            WinSelfSid,
            WinAuthenticatedUserSid,
            WinRestrictedCodeSid,
            WinTerminalServerSid,
            WinRemoteLogonIdSid,
            WinLogonIdsSid,
            WinLocalSystemSid,
            WinLocalServiceSid,
            WinNetworkServiceSid,
            WinBuiltinDomainSid,
            WinBuiltinAdministratorsSid,
            WinBuiltinUsersSid,
            WinBuiltinGuestsSid,
            WinBuiltinPowerUsersSid,
            WinBuiltinAccountOperatorsSid,
            WinBuiltinSystemOperatorsSid,
            WinBuiltinPrintOperatorsSid,
            WinBuiltinBackupOperatorsSid,
            WinBuiltinReplicatorSid,
            WinBuiltinPreWindows2000CompatibleAccessSid,
            WinBuiltinRemoteDesktopUsersSid,
            WinBuiltinNetworkConfigurationOperatorsSid,
            WinAccountAdministratorSid,
            WinAccountGuestSid,
            WinAccountKrbtgtSid,
            WinAccountDomainAdminsSid,
            WinAccountDomainUsersSid,
            WinAccountDomainGuestsSid,
            WinAccountComputersSid,
            WinAccountControllersSid,
            WinAccountCertAdminsSid,
            WinAccountSchemaAdminsSid,
            WinAccountEnterpriseAdminsSid,
            WinAccountPolicyAdminsSid,
            WinAccountRasAndIasServersSid,
            WinNTLMAuthenticationSid,
            WinDigestAuthenticationSid,
            WinSChannelAuthenticationSid,
            WinThisOrganizationSid,
            WinOtherOrganizationSid,
            WinBuiltinIncomingForestTrustBuildersSid,
            WinBuiltinPerfMonitoringUsersSid,
            WinBuiltinPerfLoggingUsersSid,
            WinBuiltinAuthorizationAccessSid,
            WinBuiltinTerminalServerLicenseServersSid,
            WinBuiltinDCOMUsersSid,
            WinBuiltinIUsersSid,
            WinIUserSid,
            WinBuiltinCryptoOperatorsSid,
            WinUntrustedLabelSid,
            WinLowLabelSid,
            WinMediumLabelSid,
            WinHighLabelSid,
            WinSystemLabelSid,
            WinWriteRestrictedCodeSid,
            WinCreatorOwnerRightsSid,
            WinCacheablePrincipalsGroupSid,
            WinNonCacheablePrincipalsGroupSid,
            WinEnterpriseReadonlyControllersSid,
            WinAccountReadonlyControllersSid,
            WinBuiltinEventLogReadersGroup,
            WinNewEnterpriseReadonlyControllersSid,
            WinBuiltinCertSvcDComAccessGroup,
            WinMediumPlusLabelSid,
            WinLocalLogonSid,
            WinConsoleLogonSid,
            WinThisOrganizationCertificateSid,
            WinApplicationPackageAuthoritySid,
            WinBuiltinAnyPackageSid,
            WinCapabilityInternetClientSid,
            WinCapabilityInternetClientServerSid,
            WinCapabilityPrivateNetworkClientServerSid,
            WinCapabilityPicturesLibrarySid,
            WinCapabilityVideosLibrarySid,
            WinCapabilityMusicLibrarySid,
            WinCapabilityDocumentsLibrarySid,
            WinCapabilitySharedUserCertificatesSid,
            WinCapabilityEnterpriseAuthenticationSid,
            WinCapabilityRemovableStorageSid,
            WinBuiltinRDSRemoteAccessServersSid,
            WinBuiltinRDSEndpointServersSid,
            WinBuiltinRDSManagementServersSid,
            WinUserModeDriversSid,
            WinBuiltinHyperVAdminsSid,
            WinAccountCloneableControllersSid,
            WinBuiltinAccessControlAssistanceOperatorsSid,
            WinBuiltinRemoteManagementUsersSid,
            WinAuthenticationAuthorityAssertedSid,
            WinAuthenticationServiceAssertedSid,
            WinLocalAccountSid,
            WinLocalAccountAndAdministratorSid,
            WinAccountProtectedUsersSid,
            WinCapabilityAppointmentsSid,
            WinCapabilityContactsSid,
            WinAccountDefaultSystemManagedSid,
            WinBuiltinDefaultSystemManagedGroupSid,
            WinBuiltinStorageReplicaAdminsSid,
            WinAccountKeyAdminsSid,
            WinAccountEnterpriseKeyAdminsSid,
            WinAuthenticationKeyTrustSid,
            WinAuthenticationKeyPropertyMFASid,
            WinAuthenticationKeyPropertyAttestationSid,
            WinAuthenticationFreshKeyAuthSid,
            WinBuiltinDeviceOwnersSid
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateWellKnownSid(
            WELL_KNOWN_SID_TYPE WellKnownSidType,
            IntPtr DomainSid,
            IntPtr pSid,
            ref uint cbSid
        );

        public struct _ACL
        {
            byte AclRevision;
            byte Sbz1;
            short AclSize;
            short AceCount;
            short Sbz2;
        }

        public enum _MULTIPLE_TRUSTEE_OPERATION
        {
            NO_MULTIPLE_TRUSTEE,
            TRUSTEE_IS_IMPERSONATE
        }

        public enum _TRUSTEE_FORM
        {
            TRUSTEE_IS_SID,
            TRUSTEE_IS_NAME,
            TRUSTEE_BAD_FORM,
            TRUSTEE_IS_OBJECTS_AND_SID,
            TRUSTEE_IS_OBJECTS_AND_NAME
        }

        public enum _TRUSTEE_TYPE
        {
            TRUSTEE_IS_UNKNOWN,
            TRUSTEE_IS_USER,
            TRUSTEE_IS_GROUP,
            TRUSTEE_IS_DOMAIN,
            TRUSTEE_IS_ALIAS,
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            TRUSTEE_IS_DELETED,
            TRUSTEE_IS_INVALID,
            TRUSTEE_IS_COMPUTER
        }

        public struct _TRUSTEE_A
        {
            public IntPtr pMultipleTrustee;
            public _MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            public _TRUSTEE_FORM TrusteeForm;
            public _TRUSTEE_TYPE TrusteeType;
            public IntPtr ptstrName;
        }

        public enum _ACCESS_MODE
        {
            NOT_USED_ACCESS,
            GRANT_ACCESS,
            SET_ACCESS,
            DENY_ACCESS,
            REVOKE_ACCESS,
            SET_AUDIT_SUCCESS,
            SET_AUDIT_FAILURE
        }

        public struct _EXPLICIT_ACCESS_A
        {
            public uint grfAccessPermissions;
            public _ACCESS_MODE grfAccessMode;
            public uint grfInheritance;
            public _TRUSTEE_A Trustee;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetEntriesInAclW(
            uint cCountOfExplicitEntries,
            ref _EXPLICIT_ACCESS_A pListOfExplicitEntries,
            IntPtr OldAcl,
            ref IntPtr NewAcl
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetSecurityInfo(
            IntPtr handle,
            _SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl
        );

        [Flags]
        public enum DesktopSecurity
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            SYNCHRONIZE = 0x00100000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,

            DESKTOP_CREATEMENU = 0x0004,
            DESKTOP_CREATEWINDOW = 0x0002,
            DESKTOP_ENUMERATE = 0x0040,
            DESKTOP_HOOKCONTROL = 0x0008,
            DESKTOP_JOURNALPLAYBACK = 0x0020,
            DESKTOP_JOURNALRECORD = 0x0010,
            DESKTOP_READOBJECTS = 0x0001,
            DESKTOP_SWITCHDESKTOP = 0x0100,
            DESKTOP_WRITEOBJECTS = 0x0080,

            GENERIC_ALL = 0x000F01FF,
        }

        [DllImport("User32.dll", SetLastError = true)]
        public static extern IntPtr OpenDesktopA(
            string lpszDesktop,
            uint dwFlags,
            bool fInherit,
            DesktopSecurity dwDesiredAccess
        );

        private const uint SECURITY_MAX_SID_SIZE = 68;

        private IntPtr ptrWinSta0 = IntPtr.Zero;
        private IntPtr pSid = IntPtr.Zero;
        private IntPtr ppSecurityDescriptor = IntPtr.Zero;
        #endregion

        internal DesktopACL()
        {
            Console.WriteLine("[*] Updating Desktop DACL");
            ptrWinSta0 = Marshal.StringToHGlobalUni("WinSta0");
        }

        //SeSecurityPrivilege
        internal void OpenWindow()
        {
            IntPtr hWinStation = OpenWindowStationW(
                ptrWinSta0, false,
                WindowStationSecurity.ACCESS_SYSTEM_SECURITY
                | WindowStationSecurity.READ_CONTROL
                | WindowStationSecurity.WRITE_DAC
            );

            if (IntPtr.Zero == hWinStation)
            {
                Misc.GetWin32Error("OpenWindowStationW");
                return;
            }
            Console.WriteLine("[+] hWinSta0 : 0x{0}", hWinStation.ToString("X4"));

            _SetDACL(hWinStation);
        }

        internal void OpenDesktop()
        {
            IntPtr hDesktop = OpenDesktopA("default", 0, false, DesktopSecurity.GENERIC_ALL | DesktopSecurity.WRITE_DAC);

            if (IntPtr.Zero == hDesktop)
            {
                Misc.GetWin32Error("OpenDesktopW");
                return;
            }
            Console.WriteLine("[+] hDesktop : 0x{0}", hDesktop.ToString("X4"));

            _SetDACL(hDesktop);
        }

        private void _SetDACL(IntPtr handle)
        { 
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr ppsidOwner, ppsidGroup, ppDacl, ppSacl;
            ppsidOwner = ppsidGroup = ppDacl = ppSacl = IntPtr.Zero;
            uint status = GetSecurityInfo(
                handle,
                _SE_OBJECT_TYPE.SE_WINDOW_OBJECT,
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                ref ppsidOwner, ref ppsidGroup, ref ppDacl, ref ppSacl, ref ppSecurityDescriptor
            );

            if (0 != status)
            {
                Misc.GetWin32Error("GetSecurityInfo");
                return;
            }
            else if (IntPtr.Zero == ppDacl)
            {
                Misc.GetWin32Error("ppDacl");
                return;
            }
            Console.WriteLine(" [+] Recieved DACL : 0x{0}", ppDacl.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            uint size = 0;
            CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, IntPtr.Zero, ref size);
            if (0 == size)
            {
                Misc.GetWin32Error("CreateWellKnownSid - Pass 1");
                return;
            }
            Console.WriteLine(" [+] Create Everyone Sid - Pass 1 : 0x{0}", size.ToString("X4"));
            pSid = Marshal.AllocHGlobal((int)size);

            if (!CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, pSid, ref size))
            {
                Misc.GetWin32Error("CreateWellKnownSid - Pass 2");
                return;
            }
            Console.WriteLine(" [+] Create Everyone Sid - Pass 2 : 0x{0}", pSid.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            _TRUSTEE_A trustee = new _TRUSTEE_A
            {
                pMultipleTrustee = IntPtr.Zero,
                MultipleTrusteeOperation = _MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
                TrusteeForm = _TRUSTEE_FORM.TRUSTEE_IS_SID,
                TrusteeType = _TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName = pSid
            };

            _EXPLICIT_ACCESS_A explicitAccess = new _EXPLICIT_ACCESS_A
            {
                grfAccessPermissions = 0xf03ff,
                grfAccessMode = _ACCESS_MODE.GRANT_ACCESS,
                grfInheritance = 1,
                Trustee = trustee
            };

            IntPtr newAcl = new IntPtr();
            status = SetEntriesInAclW(1, ref explicitAccess, ppDacl, ref newAcl);

            if (0 != status)
            {
                Misc.GetWin32Error("SetEntriesInAclW");
                return;
            }
            else if (IntPtr.Zero == newAcl)
            {
                Misc.GetWin32Error("newAcl");
                return;
            }
            Console.WriteLine(" [+] Added Everyone to DACL : 0x{0}", newAcl.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            status = SetSecurityInfo(
                handle,
                _SE_OBJECT_TYPE.SE_WINDOW_OBJECT,
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                ppsidOwner, ppsidGroup, newAcl, ppSacl
            );

            if (0 != status)
            {
                Misc.GetWin32Error("SetSecurityInfo");
                return;
            }
            Console.WriteLine(" [+] Applied DACL to Object");
        }

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

            Accctrl.TRUSTEE_W trustee = new Accctrl.TRUSTEE_W()
            {
                pMultipleTrustee = IntPtr.Zero,
                MultipleTrusteeOperation = Accctrl.MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
                TrusteeForm = Accctrl.TRUSTEE_FORM.TRUSTEE_IS_SID,
                TrusteeType = Accctrl.TRUSTEE_TYPE.TRUSTEE_IS_USER,
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
            uint retVal = advapi32.SetEntriesInAclW(1, ref explicitAccess, oldACL, ref newACL);
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

        public void Dispose()
        {
            if (IntPtr.Zero != ptrWinSta0)
                Marshal.FreeHGlobal(ptrWinSta0);

            if (IntPtr.Zero != pSid)
                Marshal.FreeHGlobal(pSid);

            if (IntPtr.Zero != ppSecurityDescriptor)
                kernel32.LocalFree(ppSecurityDescriptor);
        }

        ~DesktopACL()
        {
            Dispose();
        }
    }
}
