using System;

namespace Tokenvator
{
    class Constants
    {
        //Process Security and Access Rights
        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        public const UInt32 PROCESS_ALL_ACCESS                  = 0;
        public const UInt32 PROCESS_CREATE_PROCESS              = 0x0080;
        public const UInt32 PROCESS_CREATE_THREAD               = 0x0002;
        public const UInt32 PROCESS_DUP_HANDLE                  = 0x0040;
        public const UInt32 PROCESS_QUERY_INFORMATION           = 0x0400;
        public const UInt32 PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000;
        public const UInt32 PROCESS_SET_INFORMATION             = 0x0200;
        public const UInt32 PROCESS_SET_QUOTA                   = 0x0100;
        public const UInt32 PROCESS_SUSPEND_RESUME              = 0x0800;
        public const UInt32 PROCESS_TERMINATE                   = 0x0001;
        public const UInt32 PROCESS_VM_OPERATION                = 0x0008;
        public const UInt32 PROCESS_VM_READ                     = 0x0010;
        public const UInt32 PROCESS_VM_WRITE                    = 0x0020;
        public const UInt32 SYNCHRONIZE                         = 0x00100000;

        //Token 
        //http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
        public const UInt32 STANDARD_RIGHTS_REQUIRED    = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ        = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY        = 0x0001;
        public const UInt32 TOKEN_DUPLICATE             = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE           = 0x0004;
        public const UInt32 TOKEN_QUERY                 = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE          = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES     = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS         = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT        = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID      = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);
        public const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);

        //TOKEN_PRIVILEGES
        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
        public const UInt32 SE_PRIVILEGE_ENABLED            = 0x2;
        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
        public const UInt32 SE_PRIVILEGE_REMOVED            = 0x4;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS    = 0x3;

        public const Int32 ANYSIZE_ARRAY = 1;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
        public const String SE_ASSIGNPRIMARYTOKEN_NAME  = "SeAssignPrimaryTokenPrivilege";
        public const String SE_BACKUP_NAME              = "SeBackupPrivilege";
        public const String SE_DEBUG_NAME               = "SeDebugPrivilege";
        public const String SE_INCREASE_QUOTA_NAME      = "SeIncreaseQuotaPrivilege";
        public const String SE_TCB_NAME                 = "SeTcbPrivilege";

        public const UInt64 SE_GROUP_ENABLED            = 0x00000004L;
        public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
        public const UInt64 SE_GROUP_INTEGRITY          = 0x00000020L;
        public const UInt32 SE_GROUP_INTEGRITY_32       = 0x00000020;
        public const UInt64 SE_GROUP_INTEGRITY_ENABLED  = 0x00000040L;
        public const UInt64 SE_GROUP_LOGON_ID           = 0xC0000000L;
        public const UInt64 SE_GROUP_MANDATORY          = 0x00000001L;
        public const UInt64 SE_GROUP_OWNER              = 0x00000008L;
        public const UInt64 SE_GROUP_RESOURCE           = 0x20000000L;
        public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY  = 0x00000010L;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446583%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        public const UInt32 DISABLE_MAX_PRIVILEGE   = 0x1;
        public const UInt32 SANDBOX_INERT           = 0x2;
        public const UInt32 LUA_TOKEN               = 0x4;
        public const UInt32 WRITE_RESTRICTED        = 0x8;
    }
}
