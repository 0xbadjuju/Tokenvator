using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Principal;
using System.Threading;

using DInvoke.DynamicInvoke;

using Tokenvator.Resources;
using Tokenvator.Plugins.AccessTokens;
using Tokenvator.Plugins.Enumeration;
using Tokenvator.Plugins.Execution;
using Tokenvator.Plugins.MiniFilters;
using Tokenvator.Plugins.NamedPipes;

using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;

namespace Tokenvator
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    partial class MainLoop
    {
        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Adds a privilege via the token driver
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _AddPrivilege()
        {
            TokenDriver.PRIVILEGES priv = Misc.ParseEnum<TokenDriver.PRIVILEGES>(cLP.Privilege);

            using (TokenDriver td = new TokenDriver())
            {
                if (!td.Connect())
                {
                    Console.WriteLine("[-] Driver Connect Failed");
                    return;
                }

                Console.WriteLine("[+] Connected to Driver");
                if (cLP.Remote)
                {
                    TokenDriver.PRIVILEGE_DATA data = new TokenDriver.PRIVILEGE_DATA
                    {
                        ProcessID = (uint)cLP.ProcessID,
                        Privilege = priv,
                    };
                    td.AddTokenPrivilege(data);
                }
                else
                {
                    td.AddTokenPrivilege(priv);
                }
            }
            Console.WriteLine("[*] Disconnected from Driver");
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Enables, Disables, or Removes a privilege from a Token
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _AlterPrivilege(Winnt.TokenPrivileges attribute)
        {
            using (TokenManipulation t = new TokenManipulation(currentProcessToken))
            {
                if (cLP.Remote && !cLP.Impersonation && t.OpenProcessToken(cLP.ProcessID))
                {
                    t.SetWorkingTokenToRemote();
                }
                else if (cLP.Remote && cLP.Impersonation)
                {
                    t.ListThreads(cLP.ProcessID);
                    t.SetThreadTokenPrivilege(cLP.Privilege, attribute);
                }
                else if (!cLP.Remote && cLP.Impersonation)
                {
                    t.ListThreads(Process.GetCurrentProcess().Id);
                    t.SetThreadTokenPrivilege(cLP.Privilege, attribute);
                }
                else
                {
                    t.SetWorkingTokenToSelf();
                }
                t.SetTokenPrivilege(cLP.Privilege, attribute);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Sets the ACL for a desktop and window stations to everyone
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _ClearDesktopACL()
        {
            using (DesktopACL dA = new DesktopACL(currentProcessToken))
            {
                dA.LoadModule();
                dA.OpenWindow();
                dA.OpenDesktop();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Clones all the attributes of an existing token and creates a new one
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _CloneToken()
        {
            try
            {
                using (CreateTokens ct = new CreateTokens(currentProcessToken))
                {
                    ct.SetWorkingTokenToSelf();
                    ct.CloneToken(cLP.ProcessID, cLP.Command);
                }
            }
            catch (AccessViolationException ex)
            {
                Console.WriteLine(ex);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates a new token
        ///  https://github.com/numbnet/Win32-OpenSSH/blob/8dd7423e13ac0b88b3084ec95bc93ea09dec1fef/contrib/win32/win32compat/win32auth.c
        /// https://github.com/bb107/WinSudo/blob/b2cb7700bd2f7ee59e2ef7f9ca20c2a671ce72a8/PrivilegeHelps/Security.cpp
        /// https://www.exploit-db.com/papers/42556
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _CreateToken()
        {   
            try
            {
                using (CreateTokens ct = new CreateTokens(currentProcessToken))
                {
                    string[] groups = new string[0];
                    string g;
                    if (cLP.GetData("groups", out g))
                    {
                        groups = (g).Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                    }

                    string user;
                    if (cLP.GetData("username", out user))
                    {
                        ct.SetWorkingTokenToSelf();
                        ct.CreateToken(user, groups, cLP.Command);
                    }
                    else
                    {
                        ct.SetWorkingTokenToSelf();
                        ct.CreateToken(cLP.Command);
                    }
                }
            }
            catch (AccessViolationException ex)
            {
                Console.WriteLine(ex);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Disables a group on a tokens
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _DisableGroup()
        {
            string groups;
            if (!cLP.GetData("groups", out groups))
            {
                return;
            }

            using (TokenManipulation tm = new TokenManipulation(IntPtr.Zero))
            {
                if (cLP.Remote && tm.OpenProcessToken(cLP.ProcessID))
                    tm.SetWorkingTokenToRemote();
                else
                    tm.SetWorkingTokenToSelf();

                tm.DisableTokenGroup(groups);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Detaches a filter instanse
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _FilterDetach()
        {
            string filter;
            if (!cLP.GetData("filter", out filter))
            {
                Console.WriteLine("[-] /Filter: Not Specified");
                return;
            }

            string volume;
            if (!cLP.GetData("volume", out volume))
            {
                Console.WriteLine("[-] /Volume: Not Specified");
                return;
            }

            string instance;
            if (!cLP.GetData("instance", out instance))
            {
                Console.WriteLine("[-] /Instance: Not Specified");
                return;
            }

            using (Filters f = new Filters())
            {
                f.FilterDetach(filter, volume, instance);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Unloads a minifilter
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _FilterUnload()
        {
            string filter;
            if (!cLP.GetData("filter", out filter))
            {
                Console.WriteLine("[-] Filter Not Specified");
                return;
            }

            using (Filters f = new Filters())
            {
                f.FilterUnload(filter);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Use Native APIs to find processes that a user is running 
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _FindUserProcesses()
        {
            string user;
            if (!cLP.GetData("username", out user))
            {
                Console.WriteLine("[-] Username not specified");
                return;
            }
            Dictionary<uint, string> processes = UserSessions.EnumerateUserProcesses(user);
            Console.WriteLine("{0,-30}{1,-30}", "Process ID", "Process Name");
            Console.WriteLine("{0,-30}{1,-30}", "----------", "------------");
            foreach (uint pid in processes.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", pid, processes[pid]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Use WMI to find processes that a user is running 
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _FindUserProcessesWMI()
        {
            string user;
            if (!cLP.GetData("username", out user))
            {
                Console.WriteLine("[-] Username not specified");
                return;
            }
            Dictionary<uint, string> processes = UserSessions.EnumerateUserProcessesWMI(user);
            Console.WriteLine("{0,-30}{1,-30}", "Process ID", "Process Name");
            Console.WriteLine("{0,-30}{1,-30}", "----------", "------------");
            foreach (uint pid in processes.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", pid, processes[pid]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Impersonates a SYSTEM token or creates a new process with the duplicated token
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _GetSystem()
        {
            using (TokenInformation ti = new TokenInformation(currentProcessToken))
            {
                ti.SetWorkingTokenToSelf();
                if (!ti.CheckTokenPrivilege(Winnt.SE_DEBUG_NAME))
                {
                    using (NamedPipes np = new NamedPipes())
                    {
                        if (string.IsNullOrEmpty(cLP.Command))
                        {
                            np.GetSystem();
                        }
                        else
                        {
                            np.GetSystem(cLP.Command, cLP.Arguments);
                        }
                    }
                }
                else
                {
                    using (TokenManipulation t = new TokenManipulation(currentProcessToken))
                    {
                        t.SetWorkingTokenToSelf();

                        if (string.IsNullOrEmpty(cLP.Command))
                            t.GetSystem();
                        else
                            t.GetSystem(cLP.CommandAndArgs);
                    }
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Delegates out to _GetTrustedInstallerLogon and _GetTrustedInstallerService
        /// No Conversion Required
        /// </summary>
        /// <param name="cLP"></param>
        /// <param name="currentProcessToken"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private void _GetTrustedInstaller()
        {
            if (cLP.Legacy)
            {
                _GetTrustedInstallerService();
            }
            else
            {
                _GetTrustedInstallerLogon();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Calls LogonUserExExW with NT SERVICE\TrustedInstaller listed as a group
        /// No Conversion Required
        /// </summary>
        /// <param name="cLP"></param>
        /// <param name="currentProcessToken"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private void _GetTrustedInstallerLogon()
        {
            using (CreateTokens ct = new CreateTokens())
            {
                ct.LogonUser(
                    "NT AUTHORITY", 
                    "SYSTEM", 
                    string.Empty, 
                    "NT SERVICE\\TrustedInstaller",
                     Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE, 
                     cLP.Command, 
                     cLP.Arguments
                );
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Starts Windows Module Installer and impersonates or starts a process with 
        /// No Conversion Required
        /// </summary>
        /// <param name="cLP"></param>
        /// <param name="currentProcessToken"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private void _GetTrustedInstallerService()
        {
            using (TokenInformation ti = new TokenInformation(currentProcessToken))
            {
                ti.SetWorkingTokenToSelf();
                if (!ti.CheckTokenPrivilege(Winnt.SE_DEBUG_NAME))
                {
                    Console.WriteLine("[-] Unable to proceed");
                    return;
                }
                else
                {
                    using (TokenManipulation tm = new TokenManipulation(currentProcessToken))
                    {
                        tm.SetWorkingTokenToSelf();
                        if (string.IsNullOrEmpty(cLP.Command))
                            tm.GetTrustedInstaller();
                        else
                            tm.GetTrustedInstaller(cLP.CommandAndArgs);
                    }
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Help Menue Wrapper
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private static void _Help(string input)
        {
            string item = Misc.NextItem(ref input);
            if ("help" != item)
                _HelpItem(item);
            else
                _HelpMenu();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Displays various token information
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _Info()
        {
            using (TokenInformation t = new TokenInformation(currentProcessToken))
            {
                if (cLP.Remote)
                {
                    if (!t.OpenProcessToken(cLP.ProcessID))
                    {
                        return;
                    }
                    t.SetWorkingTokenToRemote();
                }
                else
                {
                    t.SetWorkingTokenToSelf();
                }

                //currentProcessToken = t.GetWorkingToken();

                Console.WriteLine("[*] Primary Token");
                t.GetTokenUser();
                
                Console.WriteLine();

                Console.WriteLine("[*] Impersonation Tokens");

                object obj;
                bool all = cLP.GetData("all", out obj);
                if (all)
                {
                    t.ListThreads(cLP.ProcessID);
                    t.GetThreadUsers();
                    Console.WriteLine();
                }

                Console.WriteLine("[*] Primary Token Groups");
                t.GetTokenGroups();
                Console.WriteLine();

                if (all)
                {
                    t.GetTokenSource();
                    Console.WriteLine();
                    
                    t.GetTokenPrivileges();
                    Console.WriteLine();
                    
                    t.GetTokenOwner();
                    Console.WriteLine();
                    
                    t.GetTokenPrimaryGroup();
                    Console.WriteLine();
                    
                    t.GetTokenDefaultDacl();
                    Console.WriteLine();

                    t.GetTokenType();

                    t.GetTokenElevation(true);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Installs the Token Driver
        /// sc create TokenDriver binPath="C:\Windows\System32\kerneltokens.sys" type=kernel
        /// No Conversion Required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _InstallDriver()
        {
            //string servicename = Misc.NextItem(ref command);
            //string path = Misc.NextItem(ref command);
            //string force = Misc.NextItem(ref command);

            string serviceName = "TokenDriver";
            string sn;
            if (cLP.GetData("ServiceName", out sn))
            {
                serviceName = sn;
            }

            string path = string.Empty;
            string p;
            if (cLP.GetData("Path", out p))
            {
                path = (string)p;
            }

            bool overwrite = false;
            object f;
            if (cLP.GetData("Force", out f))
            {
                overwrite = true;
            }

            Console.WriteLine("[*] Service Name: " + serviceName);
            Console.WriteLine("[*] Service Path: " + path);

            PSExec psexec = new PSExec(serviceName);

            if (!psexec.Connect("."))
            {
                Console.WriteLine("[-] Unable to connect to service controller");
                return;
            }

            string filename;
            try
            {
                filename = Path.GetFullPath(path);
            }
            catch (Exception ex)
            {
                if (ex is ArgumentException)
                {
                    filename = CreateProcess.FindFilePath(path);
                    if (string.IsNullOrEmpty(filename))
                    {
                        Console.WriteLine("[-] Unable to locate service binary");
                        return;
                    }
                }
                else
                {
                    return;
                }
            }

            Console.WriteLine("[*] Full Path: " + filename);

            if (!File.Exists(filename))
            {
                Console.WriteLine("[-] Unable to find service binary: {0}");
                return;
            }

            if (!psexec.Open())
            {
                if (!psexec.CreateDriver(filename, overwrite))
                {
                    return;
                }
                if (!psexec.Open())
                {
                    return;
                }
            }

            if (!psexec.Start())
            {
                return;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Module to check if a process is marked as critical
        /// Converted to a mix of D/Invoke Syscalls and GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="cLP"></param>
        /// <param name="hProcess"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private void _IsCriticalProcess()
        {
            IntPtr hProcess = new IntPtr();

            if (cLP.Remote)
            {
                ////////////////////////////////////////////////////////////////////////////////
                // kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, false, (uint)cLP.ProcessID);
                ////////////////////////////////////////////////////////////////////////////////
                IntPtr hNtOpenProcess = Generic.GetSyscallStub("NtOpenProcess");
                MonkeyWorks.ntdll.NtOpenProcess fSyscallNtOpenProcess = (MonkeyWorks.ntdll.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(hNtOpenProcess, typeof(MonkeyWorks.ntdll.NtOpenProcess));

                MonkeyWorks.ntdll.OBJECT_ATTRIBUTES objectAttributes = new MonkeyWorks.ntdll.OBJECT_ATTRIBUTES();
                MonkeyWorks.ntdll.CLIENT_ID clientId = new MonkeyWorks.ntdll.CLIENT_ID
                {
                    UniqueProcess = new IntPtr(cLP.ProcessID)
                };

                uint ntRetVal = 0;
                try
                {
                    ntRetVal = fSyscallNtOpenProcess(ref hProcess, ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, ref objectAttributes, ref clientId);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] NtOpenProcess Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    return;
                }

                if (0 != ntRetVal)
                {
                    Misc.GetNtError("NtOpenProcess", ntRetVal);
                    return;
                }
            }

            ////////////////////////////////////////////////////////////////////////////////
            // kernel32.IsProcessCritical(hProcess, ref bIsCritical)
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hKernel32 = Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr hIsProcessCritical = Generic.GetExportAddress(hKernel32, "IsProcessCritical");
            MonkeyWorks.kernel32.IsProcessCritical fIsProcessCritical = (MonkeyWorks.kernel32.IsProcessCritical)Marshal.GetDelegateForFunctionPointer(hIsProcessCritical, typeof(MonkeyWorks.kernel32.IsProcessCritical));

            bool bIsCritical = false;
            bool retVal = false;
            try
            {
                retVal = fIsProcessCritical(hProcess, ref bIsCritical);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtOpenProcess Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }
            
            if (!retVal)
            {
                Misc.GetWin32Error("IsProcessCritical");
                AccessTokens.CloseHandle(hProcess);
                return;
            }
            Console.WriteLine("[*] Process Critical State: {0}", bIsCritical);
            AccessTokens.CloseHandle(hProcess);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// List the loaded minifilters
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _ListFilters()
        {
            using (Filters f = new Filters())
            {
                if (!f.Load())
                {
                    return;
                }

                if (!f.First())
                {
                    return;
                }

                if (!f.Next())
                {
                    return;
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// List the instances / volumes attached to for a given minifilter
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _ListFiltersInstances()
        {
            string filter;
            if (!cLP.GetData("filter", out filter))
            {
                Console.WriteLine("[-] Filter Not Specified");
                return;
            }

            using (FilterInstance fi = new FilterInstance(filter))
            {
                if (!fi.Load())
                {
                    return;
                }

                if (!fi.First())
                {
                    return;
                }

                if (!fi.Next())
                {
                    return;
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// List the privileges for a token
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _ListPrivileges()
        {
            Console.WriteLine("Remote: " + cLP.Remote);
            Console.WriteLine("Impers: " + cLP.Impersonation);

            using (TokenInformation ti = new TokenInformation(currentProcessToken))
            {
                if (cLP.Remote && !cLP.Impersonation && ti.OpenProcessToken(cLP.ProcessID))
                {
                    ti.SetWorkingTokenToRemote();
                }
                else if (cLP.Remote && cLP.Impersonation)
                {
                    ti.ListThreads(cLP.ProcessID);
                    ti.GetThreadPrivileges();
                    return;
                }
                else if (!cLP.Remote && cLP.Impersonation)
                {
                    ti.ListThreads(Process.GetCurrentProcess().Id);
                    ti.GetThreadPrivileges();
                    return;
                }
                else
                {
                    ti.SetWorkingTokenToSelf();
                }
                ti.GetTokenPrivileges();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Logs on a user, can be used with virtual service accounts
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _LogonUser()
        {
            string username;
            if (!cLP.GetData("username", out username))
            {
                return;
            }

            string domain = ".";
            string password = string.Empty;
            Winbase.LOGON_TYPE logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_INTERACTIVE;
            if (username.Contains('\\') && !username.ToLower().StartsWith("nt service"))
            {
                string[] split = username.Split('\\').ToArray();
                domain = split.FirstOrDefault();
                username = split.LastOrDefault();
                if (!cLP.GetData("password", out password))
                {
                    Console.WriteLine("[-] Password Not Set");
                    return;
                }
                Console.WriteLine("User Logon");
            }
            else if (username.Contains('\\') && username.ToLower().StartsWith("nt service"))
            {
                string[] split = username.Split('\\').ToArray();
                username = split.LastOrDefault();
                logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE;
                Console.WriteLine("[*] Setting Logon Type to Serivce");
                domain = "NT SERVICE";
            }
            else
            {
                switch (username.ToLower().Trim())
                {
                    case "localservice":
                        username = "LocalService";
                        logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE;
                        domain = "NT AUTHORITY";
                        Console.WriteLine("[*] Setting Logon Type to Serivce");
                        break;
                    case "localsystem":
                        username = "SYSTEM";//"LocalSystem";
                        logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE;
                        domain = "NT AUTHORITY";
                        Console.WriteLine("[*] Setting Logon Type to Serivce");
                        break;
                    case "networkservice":
                        username = "Network Service";
                        logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE;
                        domain = "NT AUTHORITY";
                        Console.WriteLine("[*] Setting Logon Type to Serivce");
                        break;
                    default:
                        cLP.GetData("password", out password);
                        break;
                }
            }

            using (CreateTokens ct = new CreateTokens(currentProcessToken))
            {
                string groups;
                if (cLP.GetData("groups", out groups))
                {
                    ct.LogonUser(domain, username, password, groups, logonType, cLP.Command, cLP.Arguments);
                }
                else
                {
                    ct.LogonUser(domain, username, password, logonType, cLP.Command, cLP.Arguments);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Disable and remove all the privileges on a given token
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _NukePrivileges()
        {
            using (TokenInformation ti = new TokenInformation(currentProcessToken))
            {
                if (cLP.Remote)
                {
                    if (!ti.OpenProcessToken(cLP.ProcessID))
                    {
                        return;
                    }
                    ti.SetWorkingTokenToRemote();
                }
                else
                {
                    ti.SetWorkingTokenToSelf();
                }

                ti.GetTokenPrivileges();
                using (TokenManipulation tm = new TokenManipulation(ti.GetWorkingToken()))
                {
                    tm.SetWorkingTokenToSelf();

                    foreach (string privilege in ti.Privileges)
                    {
                        int index = CommandLineParsing.Privileges.FindIndex(x => x.Equals(privilege, StringComparison.OrdinalIgnoreCase));
                        if (-1 != index)
                        {
                            if (!tm.SetTokenPrivilege(CommandLineParsing.Privileges[index], Winnt.TokenPrivileges.SE_PRIVILEGE_REMOVED))
                            {
                                tm.SetTokenPrivilege(CommandLineParsing.Privileges[index], Winnt.TokenPrivileges.SE_PRIVILEGE_NONE);
                            }
                        }
                        else
                        {
                            Console.WriteLine("[-] Privilege \"{0}\" not indexed", privilege);
                            Console.WriteLine("[-] A bug report would be appreciated");
                        }
                        Thread.Sleep(1000);
                    }
                }

                ti.GetTokenPrivileges();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Reverts to self
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _RevertToSelf()
        {
            using (TokenManipulation tm = new TokenManipulation())
            {
                Console.WriteLine(tm.RevertToSelf() ? "[*] Reverted token to " + WindowsIdentity.GetCurrent().Name : "[-] RevertToSelf failed");
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Finds all logged on users
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _SampleProcess()
        {
            Dictionary<string, uint> users = UserSessions.EnumerateTokens(false);
            Console.WriteLine("{0,-40}{1,-20}{2}", "User", "Process ID", "Process Name");
            Console.WriteLine("{0,-40}{1,-20}{2}", "----", "----------", "------------");
            foreach (string name in users.Keys)
            {
                Console.WriteLine("{0,-40}{1,-20}{2}", name, users[name], Process.GetProcessById((int)users[name]).ProcessName);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Finds all logged on users via WMI
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _SampleProcessWMI()
        {
            Dictionary<string, uint> users = UserSessions.EnumerateTokensWMI();
            Console.WriteLine("{0,-40}{1,-20}{2}", "User", "Process ID", "Process Name");
            Console.WriteLine("{0,-40}{1,-20}{2}", "----", "----------", "------------");
            foreach (string name in users.Keys)
            {
                Console.WriteLine("{0,-40}{1,-20}{2}", name, users[name], Process.GetProcessById((int)users[name]).ProcessName);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Marks or unmarks a process as being critical
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="cLP"></param>
        /// <param name="hProcess"></param>
        ////////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [HandleProcessCorruptedStateExceptions]
        private void _SetCriticalProcess()
        {
            IntPtr hProcess = new IntPtr();

            string sSetting;
            cLP.GetData("state", out sSetting);

            bool bSetting;
            if (!bool.TryParse(sSetting, out bSetting))
            {
                Console.WriteLine("[-] Invalid Boolean Specified: {0}", sSetting);
                return;
            }

            uint uSetting = Convert.ToUInt32(bSetting);
            if (cLP.Remote)
            {
                ////////////////////////////////////////////////////////////////////////////////
                // kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_SET_INFORMATION, false, (uint)cLP.ProcessID);
                ////////////////////////////////////////////////////////////////////////////////
                IntPtr hNtOpenProcess = Generic.GetSyscallStub("NtOpenProcess");
                MonkeyWorks.ntdll.NtOpenProcess fSyscallNtOpenProcess = (MonkeyWorks.ntdll.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(hNtOpenProcess, typeof(MonkeyWorks.ntdll.NtOpenProcess));

                MonkeyWorks.ntdll.OBJECT_ATTRIBUTES objectAttributes = new MonkeyWorks.ntdll.OBJECT_ATTRIBUTES();
                MonkeyWorks.ntdll.CLIENT_ID clientId = new MonkeyWorks.ntdll.CLIENT_ID
                {
                    UniqueProcess = new IntPtr(cLP.ProcessID)
                };

                uint retVal = 0;
                try
                {
                    retVal = fSyscallNtOpenProcess(ref hProcess, ProcessThreadsApi.ProcessSecurityRights.PROCESS_SET_INFORMATION, ref objectAttributes, ref clientId);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] NtOpenProcess Generated an Exception");
                    Console.WriteLine("[-] {0}", ex.Message);
                    return;
                }

                if (0 != retVal)
                {
                    Misc.GetNtError("NtOpenProcess", retVal);
                    return;
                }
            }

            ////////////////////////////////////////////////////////////////////////////////
            // ntdll.NtSetInformationProcess(hProcess, ntdll._PROCESS_INFORMATION_CLASS.ProcessBreakOnTermination, ref uSetting, (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(uint)));
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hNtSetInformationProcess = Generic.GetSyscallStub("NtSetInformationProcess");
            MonkeyWorks.ntdll.NtSetInformationProcess fSyscallNtSetInformationProcess = (MonkeyWorks.ntdll.NtSetInformationProcess)Marshal.GetDelegateForFunctionPointer(hNtSetInformationProcess, typeof(MonkeyWorks.ntdll.NtSetInformationProcess));

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtSetInformationProcess(hProcess, MonkeyWorks.ntdll._PROCESS_INFORMATION_CLASS.ProcessBreakOnTermination, ref uSetting, (uint)Marshal.SizeOf(typeof(uint)));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtOpenProcess Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtSetInformationProcess", ntRetVal);
                AccessTokens.CloseHandle(hProcess);
                return;
            }

            if (bSetting)
            {
                Console.WriteLine("[+] Process {0} is Marked as Critical", cLP.ProcessID);
            }
            else
            {
                Console.WriteLine("[+] Process {0} is Unmarked as Critical", cLP.ProcessID);
            }

            AccessTokens.CloseHandle(hProcess);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Starts the KernelTokens Driver
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _StartDriver()
        {
            string sn;
            if (!cLP.GetData("ServiceName", out sn))
            {
                Console.WriteLine("[-] ServiceName not set");
                return;
            }

            PSExec p = new PSExec(sn);
            if (!p.Connect("."))
            {
                Console.WriteLine("[-] Unable to connect to service controller");
                return;
            }
            if (!p.Start())
            {
                return;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Duplicates a token from another process - either impersonates or creates a 
        /// new process
        /// No conversions required
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        private bool _StealToken()
        {
            using (TokenManipulation t = new TokenManipulation(currentProcessToken))
            {
                
                if (string.IsNullOrWhiteSpace(cLP.Command))
                {
                    if (0 != cLP.ProcessID && t.OpenProcessToken(cLP.ProcessID))
                    {
                        t.SetWorkingTokenToRemote();
                    }
                    else if (0 != cLP.ThreadID && t.OpenThreadToken((uint)cLP.ThreadID, Winnt.TOKEN_ALL_ACCESS))
                    {
                        t.SetWorkingTokenToThreadToken();
                    }
                    else
                    {
                        Console.WriteLine("[-] Process or Thread ID not Specified");
                        return false;
                    }

                    if (t.ImpersonateUser())
                    {
                        return true;
                    }
                }
                else
                {
                    if (0 != cLP.ProcessID && t.OpenProcessToken(cLP.ProcessID))
                    {
                        t.SetWorkingTokenToRemote();
                        if (!t.DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, Winnt._TOKEN_TYPE.TokenPrimary))
                        {
                            return false;
                        }
                        t.SetWorkingTokenToNewToken();
                    }
                    else if (0 != cLP.ThreadID && t.OpenThreadToken((uint)cLP.ThreadID, Winnt.TOKEN_ALL_ACCESS))
                    {
                        t.SetWorkingTokenToThreadToken();
                    }
                    else
                    {
                        Console.WriteLine("[-] Process or Thread ID not Specified");
                        return false;
                    }

                    if (t.StartProcessAsUser(cLP.Command))
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Steal a token from a named pipe, has some wierd corner cases
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _StealPipeToken()
        {
            if (string.IsNullOrEmpty(cLP.PipeName))
            {
                Console.WriteLine("[-] Pipename not set");
                return;
            }

            if (string.IsNullOrEmpty(cLP.Command))
            {
                using (NamedPipes np = new NamedPipes())
                {
                    np.GetPipeToken(cLP.PipeName);
                }

                Console.WriteLine("[*] Operating as {0}", WindowsIdentity.GetCurrent().Name);
            }
            else
            {
                Console.WriteLine("[*] Running {0}", cLP.CommandAndArgs);
                using (NamedPipes np = new NamedPipes())
                {
                    np.GetPipeToken(cLP.PipeName, cLP.Command, cLP.Arguments);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Read command input for the Run Command
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _SubProcessStdIn()
        {
            try
            {
                var reader = new StreamReader(Console.OpenStandardInput());
                while (!reader.EndOfStream)
                {
                    process.StandardInput.WriteLine(reader.ReadLine());
                }
            }
            catch (Exception ex)
            {
                if (!(ex is ThreadAbortException))
                {
                    Console.Error.WriteLine("GiveProcStdIn:" + ex.Message);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Read command input for the Run Command
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _SubProcessStdOut()
        {
            try
            {
                StreamReader reader = process.StandardOutput;
                while (!reader.EndOfStream)
                {
                    Console.WriteLine(reader.ReadLine());
                }

                reader = process.StandardError;
                while (!reader.EndOfStream)
                {
                    Console.WriteLine(reader.ReadLine());
                }
            }
            catch (Exception ex)
            {
                if (!(ex is ThreadAbortException))
                {
                    Console.Error.WriteLine("ShowProcStdOut:" + ex.Message);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Terminates a given process
        /// Converted to D/Invoke Syscalls
        /// </summary>
        /// <param name="cLP"></param>
        /// <param name="hProcess"></param>
        ////////////////////////////////////////////////////////////////////////////////
        private void _Terminate()
        {
            IntPtr hProcess = new IntPtr();

            ////////////////////////////////////////////////////////////////////////////////
            // kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_SET_INFORMATION, false, (uint)cLP.ProcessID);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hNtOpenProcess = Generic.GetSyscallStub("NtOpenProcess");
            MonkeyWorks.ntdll.NtOpenProcess fSyscallNtOpenProcess = (MonkeyWorks.ntdll.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(hNtOpenProcess, typeof(MonkeyWorks.ntdll.NtOpenProcess));

            MonkeyWorks.ntdll.OBJECT_ATTRIBUTES objectAttributes = new MonkeyWorks.ntdll.OBJECT_ATTRIBUTES();
            MonkeyWorks.ntdll.CLIENT_ID clientId = new MonkeyWorks.ntdll.CLIENT_ID
            {
                UniqueProcess = new IntPtr(cLP.ProcessID)
            };

            uint ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtOpenProcess(ref hProcess, ProcessThreadsApi.ProcessSecurityRights.PROCESS_TERMINATE, ref objectAttributes, ref clientId);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtOpenProcess Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtOpenProcess", ntRetVal);
                return;
            }

            Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));

            ////////////////////////////////////////////////////////////////////////////////
            // kernel32.TerminateProcess(hProcess, 0)
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hNtTerminateProcess = Generic.GetSyscallStub("NtTerminateProcess");
            MonkeyWorks.ntdll.NtTerminateProcess fSyscallNtTerminateProcess = (MonkeyWorks.ntdll.NtTerminateProcess)Marshal.GetDelegateForFunctionPointer(hNtOpenProcess, typeof(MonkeyWorks.ntdll.NtTerminateProcess));

            ntRetVal = 0;
            try
            {
                ntRetVal = fSyscallNtTerminateProcess(hProcess, 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] NtTerminateProcess Generated an Exception");
                Console.WriteLine("[-] {0}", ex.Message);
                return;
            }
            finally
            {
                AccessTokens.CloseHandle(hProcess);
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtTerminateProcess", ntRetVal);
                return;
            }

            Console.WriteLine("[+] Process Terminated");
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Unfreezes a token via a driver
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _UnfreezeToken()
        {
            using (TokenDriver td = new TokenDriver())
            {
                if (!td.Connect())
                {
                    Console.WriteLine("[-] Driver Connect Failed");
                    return;
                }
                if (cLP.Remote)
                {
                    td.UnFreezeToken((uint)cLP.ProcessID);
                }
                else
                {
                    td.UnFreezeToken();
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Uninstalls the token driver
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _UnInstallDriver()
        {
            string service;
            if (cLP.GetData("servicename", out service))
            {
                using (PSExec p = new PSExec(service))
                {
                    if (!p.Connect("."))
                        return;

                    if (!p.Open())
                        return;

                    if (!p.Stop())
                        return;

                    if (!p.Delete())
                        return;
                }
            }
            else
            {
                Console.WriteLine("[-] Unable to identify /Service");
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Runs a cmd prompt command
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _Run()
        {
            process = new Process();
            process.StartInfo.FileName = cLP.Command;
            process.StartInfo.Arguments = cLP.Arguments;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardInput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.RedirectStandardOutput = true;
            Console.WriteLine("[+] Starting {0}", cLP.CommandAndArgs);
            Console.WriteLine("[*] Note: The prompt is currently missing for input");
            Console.WriteLine();
            process.Start();

            Thread inThread = new Thread(() => _SubProcessStdIn());
            Thread outThread = new Thread(() => _SubProcessStdOut());
            inThread.Start();
            outThread.Start();

            process.WaitForExit();

            inThread.Abort();
            outThread.Abort();
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Emulates the functionality for runas /netonly
        /// Migrated to Move this to CreateTokens & CreateProcess
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _RunAsNetOnly()
        {
            string[] domain_user;
            string domain;
            string username;

            string un;
            if (!cLP.GetData("username", out un))
            {
                Console.WriteLine("[-] Username not specified");
                return;
            }

            string userInfo = un;
            if (userInfo.Contains("\\"))
            {
                domain_user = userInfo
                    .Split(new string[] { "\\" }, StringSplitOptions.RemoveEmptyEntries);
                domain = (2 == domain_user.Length) ? domain_user[0] : ".";
                username = (2 == domain_user.Length) ? domain_user[1] : domain_user[0];
            }
            else if (userInfo.Contains("@"))
            {
                domain_user = userInfo
                    .Split(new string[] { "@" }, StringSplitOptions.RemoveEmptyEntries);
                domain = (2 == domain_user.Length) ? domain_user[1] : ".";
                username = domain_user[0];
            }
            else
            {
                domain = ".";
                username = userInfo;
            }

            string password;
            if (!cLP.GetData("password", out password))
            {
                Console.WriteLine("[-] Password not specified");
                return;
            }

            Console.WriteLine("[*] Username: {0}", username);
            Console.WriteLine("[*] Domain:   {0}", domain);
            Console.WriteLine("[*] Password: {0}", password);

            if (string.IsNullOrEmpty(cLP.Command))
            {
                using(CreateTokens ct = new CreateTokens())
                {
                    ct.LogonUser(
                        domain,
                        username,
                        password,
                        Winbase.LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS, 
                        string.Empty, 
                        string.Empty
                    );
                }
            }
            else
            {
                Console.WriteLine("[*] Command: {0}", cLP.Command);

                CreateProcess.CreateProcessWithLogonW(username, domain, password, cLP.Command, cLP.Arguments);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Pass through powershell command
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private void _RunPowerShell()
        {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(cLP.Command);
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();

            foreach (PSObject obj in results)
            {
                Console.WriteLine(obj.ToString());
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Prints the generic help menu that lists the commands
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private static void _HelpMenu()
        {
            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "Name", "Optional", "Required");
            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "----", "--------", "--------");
            for (int i = 0; i < options.GetLength(0); i++)
            {
                Console.WriteLine("{0,-25}{1,-20}{2,-20}", options[i, 0], options[i, 1], options[i, 2]);
            }
            Console.WriteLine("e.g. (Tokens)> Help List_Filter_Instances");
            Console.WriteLine("e.g. (Tokens)> Help Privileges");
            Console.WriteLine("");
            Console.WriteLine("e.g. (Tokens)> Steal_Token /Process:27015");
            Console.WriteLine("e.g. (Tokens)> Steal_Token /Process:27015 /Command:cmd.exe");
            Console.WriteLine("e.g. (Tokens)> Enable_Privilege /Privilege:SeDebugPrivilege");
            Console.WriteLine("e.g. (Tokens)> Enable_Privilege /Process:27015 /Privilege:SeDebugPrivilege");
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Prints an example for a specific command
        /// No conversions required
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        private static void _HelpItem(string input)
        {
            if ("privileges" == input.ToLower())
            {
                foreach (string item in CommandLineParsing.Privileges)
                {
                    Console.WriteLine(item);
                }
                return;
            }

            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "Name", "Optional", "Required");
            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "----", "--------", "--------");
            for (int i = 0; i < options.GetLength(0); i++)
            {
                if (input.ToLower() == options[i, 0].ToLower())
                {
                    Console.WriteLine("{0,-25}{1,-20}{2,-20}", options[i, 0], options[i, 1], options[i, 2]);
                    Console.WriteLine(" ");
                    Console.WriteLine("e.g. (Tokens)> {0}", options[i, 3]);
                    return;
                }
            }

        }
    }

    public static class ProcessExtensions
    {
        private static string FindIndexedProcessName(int pid)
        {
            var processName = Process.GetProcessById(pid).ProcessName;
            var processesByName = Process.GetProcessesByName(processName);
            string processIndexdName = null;

            for (var index = 0; index < processesByName.Length; index++)
            {
                processIndexdName = index == 0 ? processName : processName + "#" + index;
                var processId = new PerformanceCounter("Process", "ID Process", processIndexdName);
                if ((int)processId.NextValue() == pid)
                {
                    return processIndexdName;
                }
            }

            return processIndexdName;
        }

        private static Process FindPidFromIndexedProcessName(string indexedProcessName)
        {
            var parentId = new PerformanceCounter("Process", "Creating Process ID", indexedProcessName);
            return Process.GetProcessById((int)parentId.NextValue());
        }

        public static Process Parent(this Process process)
        {
            return FindPidFromIndexedProcessName(FindIndexedProcessName(process.Id));
        }
    }
}
