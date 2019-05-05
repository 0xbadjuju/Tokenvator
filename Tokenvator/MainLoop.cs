using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;

using Tokenvator.Enumeration;
using Tokenvator.MiniFilters;
using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    partial class MainLoop
    {
        private static string context = "(Tokens) > ";
        public static string[,] options = new string[,] {
            {"Info", "-", "-", "-"},
            {"Help", "Command", "-", "Help List_Filter_Instances"},

            {"List_Privileges", "ProcessID", "-", "List_Privileges 2180"},
            {"Enable_Privilege", "ProcessID", "Privilege", "Enable_Privilege 2180 SeShutdownPrivilege"},
            {"Disable_Privilege", "ProcessID", "Privilege", "Disable_Privilege 2180 SeShutdownPrivilege"},
            {"Remove_Privilege", "ProcessID", "Privilege", "Remove_Privilege 2180 SeShutdownPrivilege"},
            {"Nuke_Privileges", "ProcessID", "-", "Nuke_Privileges 2180"},

            {"Terminate", "ProcessID", "-", "Terminate 2180"},

            {"GetSystem", "Command", "-", "GetSystem | GetSystem cmd.exe /c powershell.exe"},
            {"GetTrustedInstaller", "Command", "-", "GetTrustedInstaller | cmd.exe /c powershell.exe"},
            {"Steal_Token", "Command", "ProcessID", "Steal_Token 2180 | Steal_Token 2180 cmd.exe"},
            {"Steal_Pipe_Token", "Command", "PipeName", @"Steal_Pipe_Token \\.\pipe\tokenvator | Steal_Pipe_Token \\.\pipe\tokenvator cmd.exe"},
            {"BypassUAC", "ProcessID", "Command", "BypassUAC cmd.exe| BypassUAC 892 cmd.exe"},

            {"Tasklist", "-", "-", "Tasklist"},
            {"Sample_Processes", "-", "-", "Sample_Processes"},
            {"Sample_Processes_WMI", "-", "-", "Sample_Processes"},

            {"Find_User_Processes", "-", "User", "Find_User_Processes Administrator"},
            {"Find_User_Processes_WMI", "-", "User", "Find_User_Processes_WMI Administrator"},

            {"List_Filters", "-", "-", "List_Filters"},
            {"List_Filter_Instances", "-", "FilterName", "List_Filter_Instances vsepflt"},
            {"Detach_Filter", "InstanceName", "FilterName, VolumeName", @"Detach_Filter vsepflt \Device\Mup vsepflt Instance"},
            {"Unload_Filter", "-", "FilterName", "Unload_Filter vsepflt"},


            {"Sessions", "-", "-", "Sessions"},
            {"WhoAmI", "-", "-", "WhoAmI"},
            {"RevertToSelf", "-", "-", "RevertToSelf"},
            {"Run", "-", "Command", "Run ipconfig"},
            {"RunPowerShell", "-", "Command", "RunPowerShell Get-ChildItem"},
            {"", "", "", ""}
        };

        private IntPtr hProcess;
        private readonly IntPtr hBackup;
        private int processID;
        private string command;

        private static Process process;

        private readonly TabComplete console;
        private readonly bool activateTabs;

        public MainLoop(bool activateTabs)
        {
            this.activateTabs = activateTabs;
            if (activateTabs)
            {
                console = new TabComplete(context, options);
            }

            hProcess = kernel32.GetCurrentProcess();
            hBackup = hProcess;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal void Run()
        {
            try
            {
                Console.Write(context);
                string input;
                if (activateTabs)
                {
                    try
                    {
                        input = console.ReadLine();
                    }
                    catch (InvalidOperationException)
                    {
                        input = Console.ReadLine();
                    }
                }
                else
                {
                    input = Console.ReadLine();
                }

                IntPtr hToken, tempToken;
                hToken = tempToken = IntPtr.Zero;

                bool remote = _GetProcessID(input, out processID, out command);
                if (!remote)
                {
                    hProcess = hBackup;
                    kernel32.OpenProcessToken(hProcess, Constants.TOKEN_ALL_ACCESS, out hToken);
                    if (IntPtr.Zero == hToken)
                    {
                        Console.WriteLine("[-] Opening Process Token Failed, Opening Thread Token");
                        IntPtr hThread = kernel32.GetCurrentThread();
                        kernel32.OpenThreadToken(hThread, Constants.TOKEN_ALL_ACCESS, true, ref hToken);
                        if (IntPtr.Zero == hToken)
                        {
                            Console.WriteLine("[-] Opening Thread Token Failed, Recommend RevertToSelf");
                        }
                    }
                }

                switch (Misc.NextItem(ref input))
                {
                    case "add_privilege":
                        _AddPrivilege(remote, processID, command);
                        break;
                    case "bypassuac":
                        _BypassUAC(remote, processID, command, input, hToken);
                        break;
                    case "clear_desktop_acl":
                        _ClearDesktopACL();
                        break;
                    case "clone_token":
                        _CloneToken(remote, processID, command, hToken);
                        break;
                    case "detach_filter":
                        Filters.FilterDetach(input);
                        break;
                    case "disable_privilege":
                        _AlterPrivilege(remote, processID, command, hToken, Winnt.TokenPrivileges.SE_PRIVILEGE_NONE);
                        break;
                    case "enable_privilege":
                        _AlterPrivilege(remote, processID, command, hToken, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);
                        break;
                    case "exit":
                        Environment.Exit(0);
                        break;
                    case "find_user_processes":
                        _FindUserProcesses(input);
                        break;
                    case "find_user_processes_wmi":
                        _FindUserProcessesWMI(input);
                        break;
                    case "getsystem":
                        _GetSystem(input, hToken);
                        break;
                    case "gettrustedinstaller":
                        _GetTrustedInstaller(input, hToken);
                        break;
                    case "help":
                        _Help(input);
                        break;
                    case "info":
                        _Info(remote, processID, hToken);
                        break;
                    case "install_driver":
                        _InstallDriver(command);
                        break;
                    case "list_filters":
                        _ListFilters();
                        break;
                    case "list_filter_instances":
                        _ListFiltersInstances(input);
                        break;
                    case "list_privileges":
                        _ListPrivileges(remote, processID, hToken);
                        break;
                    case "logon_user":
                        _LogonUser(input, hToken);
                        break;
                    case "nuke_privileges":
                        _NukePrivileges(remote, processID, hToken);
                        break;
                    case "remove_privilege":
                        _AlterPrivilege(remote, processID, command, hToken, Winnt.TokenPrivileges.SE_PRIVILEGE_REMOVED);
                        break;
                    case "is_critical_process":
                        _IsCriticalProcess(remote, processID, hProcess);
                        break;
                    case "set_critical_process":
                        _SetCriticalProcess(remote, processID, command, hProcess);
                        break;
                    case "reverttoself":
                        Console.WriteLine(advapi32.RevertToSelf() ? "[*] Reverted token to " + WindowsIdentity.GetCurrent().Name : "[-] RevertToSelf failed");
                        break;
                    case "run":
                        _Run(input);
                        break;
                    case "runpowershell":
                        _RunPowerShell(input);
                        break;
                    case "sample_processes":
                        _SampleProcess();
                        break;
                    case "sample_processes_wmi":
                        _SampleProcessWMI();
                        break;
                    case "sessions":
                        UserSessions.EnumerateInteractiveUserSessions();
                        break;
                    case "steal_pipe_token":
                        _StealPipeToken(input);
                        break;
                    case "steal_token":
                        _StealToken(remote, processID, command, hToken);
                        break;
                    case "tasklist":
                        UserSessions.Tasklist();
                        break;
                    case "terminate":
                        _Terminate(remote, processID, hProcess);
                        break;
                    case "unfreeze_token":
                        _UnfreezeToken(remote, processID);
                        break;
                    case "uninstall_driver":
                        _UnInstallDriver(command);
                        break;
                    case "unload_filter":
                        Filters.Unload(Misc.NextItem(ref input));
                        break;
                    case "whoami":
                        Console.WriteLine("[*] Operating as {0}", WindowsIdentity.GetCurrent().Name);
                        break;
                    default:
                        _Help(input);
                        break;
                }

                if (IntPtr.Zero != hToken)
                    kernel32.CloseHandle(hToken);
            }
            catch (Exception error)
            {
                Console.WriteLine(error.ToString());
                Misc.GetWin32Error("MainLoop");
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Identifies a process to access
        ////////////////////////////////////////////////////////////////////////////////
        private static bool _GetProcessID(string input, out int processID, out string command)
        {
            string name = Misc.NextItem(ref input);
            command = string.Empty;

            string arg1 = Misc.NextItem(ref input);
            if (int.TryParse(arg1, out processID))
            {
                if (arg1 != input)
                {
                    command = input;
                }
                return true;
            }

            Process[] process = Process.GetProcessesByName(arg1);
            if (0 < process.Length)
            {
                processID = process.First().Id;
                if (arg1 != input)
                {
                    command = input;
                }
                return true;
            }

            if (arg1 != input)
            {
                command = input;
            }
            return false;
        }
    }
}
