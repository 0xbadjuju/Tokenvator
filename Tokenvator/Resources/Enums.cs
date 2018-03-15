using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Tokenvator
{
    class Enums
    {
        [Flags]
        public enum LOGON_FLAGS
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms682434(v=vs.85).aspx
        [Flags]
        public enum CREATION_FLAGS
        {
            NONE = 0x0,
            CREATE_DEFAULT_ERROR_MODE       = 0x04000000,
            CREATE_NEW_CONSOLE              = 0x00000010,
            CREATE_NEW_PROCESS_GROUP        = 0x00000200,
            CREATE_SEPARATE_WOW_VDM         = 0x00000800,
            CREATE_SUSPENDED                = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT      = 0x00000400,
            EXTENDED_STARTUPINFO_PRESENT    = 0x00080000
        }



        [Flags]
        public enum _SECURITY_IMPERSONATION_LEVEL : int
        {
            SecurityAnonymous       = 0,
            SecurityIdentification  = 1,
            SecurityImpersonation   = 2,
            SecurityDelegation      = 3
        };

        [Flags]
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        //http://www.pinvoke.net/default.aspx/Enums.ACCESS_MASK
        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE                      = 0x00010000,
            READ_CONTROL                = 0x00020000,
            WRITE_DAC                   = 0x00040000,
            WRITE_OWNER                 = 0x00080000,
            SYNCHRONIZE                 = 0x00100000,
            STANDARD_RIGHTS_REQUIRED    = 0x000F0000,
            STANDARD_RIGHTS_READ        = 0x00020000,
            STANDARD_RIGHTS_WRITE       = 0x00020000,
            STANDARD_RIGHTS_EXECUTE     = 0x00020000,
            STANDARD_RIGHTS_ALL         = 0x001F0000,
            SPECIFIC_RIGHTS_ALL         = 0x0000FFF,
            ACCESS_SYSTEM_SECURITY      = 0x01000000,
            MAXIMUM_ALLOWED             = 0x02000000,
            GENERIC_READ                = 0x80000000,
            GENERIC_WRITE               = 0x40000000,
            GENERIC_EXECUTE             = 0x20000000,
            GENERIC_ALL                 = 0x10000000,
            DESKTOP_READOBJECTS         = 0x00000001,
            DESKTOP_CREATEWINDOW        = 0x00000002,
            DESKTOP_CREATEMENU          = 0x00000004,
            DESKTOP_HOOKCONTROL         = 0x00000008,
            DESKTOP_JOURNALRECORD       = 0x00000010,
            DESKTOP_JOURNALPLAYBACK     = 0x00000020,
            DESKTOP_ENUMERATE           = 0x00000040,
            DESKTOP_WRITEOBJECTS        = 0x00000080,
            DESKTOP_SWITCHDESKTOP       = 0x00000100,
            WINSTA_ENUMDESKTOPS         = 0x00000001,
            WINSTA_READATTRIBUTES       = 0x00000002,
            WINSTA_ACCESSCLIPBOARD      = 0x00000004,
            WINSTA_CREATEDESKTOP        = 0x00000008,
            WINSTA_WRITEATTRIBUTES      = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS    = 0x00000020,
            WINSTA_EXITWINDOWS          = 0x00000040,
            WINSTA_ENUMERATE            = 0x00000100,
            WINSTA_READSCREEN           = 0x00000200,
            WINSTA_ALL_ACCESS           = 0x0000037F
        };

        public enum SECURITY_IMPERSONATION_LEVEL
        {
             SecurityAnonymous,
             SecurityIdentification,
             SecurityImpersonation,
             SecurityDelegation
        }

        public enum _TOKEN_INFORMATION_CLASS { 
            TokenUser                             = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }

        public enum _SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel
        }

        internal enum CRED_FLAGS : uint
        {
            NONE = 0x0,
            PROMPT_NOW = 0x2,
            USERNAME_TARGET = 0x4
        }

        internal enum CRED_PERSIST : uint
        {
            Session = 1,
            LocalMachine,
            Enterprise
        }

        internal enum CRED_TYPE : uint
        {
            Generic = 1,
            DomainPassword,
            DomainCertificate,
            DomainVisiblePassword,
            GenericCertificate,
            DomainExtended,
            Maximum,
            MaximumEx = Maximum + 1000,
        }

        internal enum TOKEN_ELEVATION_TYPE
        {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }
    }
}
