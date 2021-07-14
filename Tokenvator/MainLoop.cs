using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;

using Tokenvator.Plugins.Enumeration;
using Tokenvator.Plugins.MiniFilters;
using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    partial class MainLoop
    {
        private static string context = "(Tokens) > ";
        public static string[,] options = new string[,] {
            {"Info", "all", "-", "Info /All"},
            {"Help", "Command", "-", "Help List_Filter_Instances"},
            {"History", "-", "-", "History"},
            {"", "", "", ""},

            {"Add_Privilege", "Process", "Privilege", "Add_Privileges /Privilege:SeCreateTokenPrivilege"},
            {"List_Privileges", "Process", "-", "List_Privileges /Process:powershell.exe \nList_Privileges /Process:27015"},
            {"Enable_Privilege", "Process", "Privilege", "Enable_Privilege /Process:2180 /Privilege:SeShutdownPrivilege \nEnable_Privilege /Process:powershell.exe /Privilege:SeShutdownPrivilege"},
            {"Disable_Privilege", "Process", "Privilege", "Disable_Privilege /Process:2180 /Privilege:SeShutdownPrivilege \nDisable_Privilege /Process:powershell.exe /Privilege:SeShutdownPrivilege"},
            {"Remove_Privilege", "Process", "Privilege", "Remove_Privilege /Process:2180 /Privilege:SeShutdownPrivilege \nRemove_Privilege /Process:powershell.exe /Privilege:SeShutdownPrivilege"},
            {"Nuke_Privileges", "Process", "-", "Nuke_Privileges /Process:2180 \nNuke_Privileges /Process:powershell.exe"},
            {"", "", "", ""},
            
            {"GetSystem", "Command", "-", "GetSystem \nGet_System \nGetSystem /command:cmd.exe /c start powershell.exe"},
            {"GetTrustedInstaller", "Command", "-", "GetTrustedInstaller \nGet_TrustedInstaller \nGetTrustedInstaller /command:\"cmd.exe /c powershell.exe\""},
            {"Steal_Token", "Command", "Process", "Steal_Token /Process:2180 | Steal_Token /Process:2180 /Command:cmd.exe"},
            {"Steal_Pipe_Token", "Command", "PipeName", @"Steal_Pipe_Token /PipeName:\\.\pipe\tokenvator \nSteal_Pipe_Token /PipeName:tokenvator /command:cmd.exe"},
            {"BypassUAC", "ProcessID", "Command", "BypassUAC /Command:cmd.exe \nBypassUAC /Process:892 /Command:cmd.exe"},
            {"", "", "", ""},

            {"Tasklist", "-", "-", "Tasklist"},
            {"Sample_Processes", "-", "-", "Sample_Processes"},
            {"Sample_Processes_WMI", "-", "-", "Sample_Processes_WMI"},
            {"Find_User_Processes", "-", "User", "Find_User_Processes /User:Administrator"},
            {"Find_User_Processes_WMI", "-", "User", "Find_User_Processes_WMI /User:Administrator"},
            {"", "", "", ""},

            {"List_Filters", "-", "-", "List_Filters"},
            {"List_Filter_Instances", "-", "Filter", "List_Filter_Instances /Filter:vsepflt"},
            {"Detach_Filter", "Instance", "Filter, Volume", "Detach_Filter /Filter:vsepflt /Volume:\\Device\\Mup /Instance:\"vsepflt Instance\""},
            {"Unload_Filter", "-", "Filter", "Unload_Filter /Filter:vsepflt"},
            {"", "", "", ""},

            {"Clear_Desktop_Acl", "-", "-", "Clear_Desktop_Acl"},
            {"", "", "", ""},

            {"Install_Driver", "-", "ServiceName, DriverFilePath", "Install_Driver /ServiceName:TokenDriver /Path:C:\\Share\\KernelTokens.sys"},
            {"Start_Driver", "-", "ServiceName", "Start_Driver /ServiceName:TokenDriver"},
            {"UnInstall_Driver", "-", "ServiceName", "UnInstall_Driver /ServiceNameTokenDriver"},
            {"", "", "", ""},

            {"RunAs", "Command", "UserName, Password", "RunAs /Username:Administrator /Password:Password1 /Command:cmd.exe"},
            {"Logon_User", "Command, Password, Groups", "UserName", "logon_user /Username:networkservice /Command:cmd.exe"},
            {"Create_Token", "UserName, Groups", "Command", "Create_Token /User:Administrator /Groups:tvator_group,sql_admins_group /Command"},
            {"", "", "", ""},

            {"Terminate", "Process", "-", "Terminate /Process:2180"},
            {"Is_Critical_Process", "Process", "-", "Is_Critical_Process /Process:word.exe"},
            {"Set_Critical_Process", "Process", "-", "Set_Critical_Process /Process:excel.exe /true \nSet_Critical_Process /Process:excel.exe"},
            {"", "", "", ""},

            {"Sessions", "-", "-", "Sessions"},
            {"PID", "-", "-", "PID"},
            {"WhoAmI", "-", "-", "WhoAmI"},
            {"RevertToSelf", "-", "-", "RevertToSelf"},
            {"Run", "-", "Command", "run cmd.exe \nrun /command:\"cmd.exe /c start cmd.exe\""},
            {"RunPowerShell", "-", "Command", "RunPowerShell \nRunPowerShell /Command:Get-ChildItem"},
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
        // Mainloop
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
                    kernel32.OpenProcessToken(hProcess, Winnt.TOKEN_ALL_ACCESS, out hToken);
                    if (IntPtr.Zero == hToken)
                    {
                        Console.WriteLine("[-] Opening Process Token Failed, Opening Thread Token");
                        IntPtr hThread = kernel32.GetCurrentThread();
                        kernel32.OpenThreadToken(hThread, Winnt.TOKEN_ALL_ACCESS, true, ref hToken);
                        if (IntPtr.Zero == hToken)
                        {
                            Console.WriteLine("[-] Opening Thread Token Failed, Recommend RevertToSelf");
                        }
                    }
                }
                string action = Misc.NextItem(ref input);
                CommandLineParsing cLP = new CommandLineParsing();
                if (!string.Equals(action, input, StringComparison.OrdinalIgnoreCase))
                {
                    if (!cLP.Parse(input))
                    {
                        return;
                    }    
                }

                switch (action)
                {
                    case "add_group":
                        _AddGroup(cLP, hToken);
                        break;
                    case "add_privilege":
                        _AddPrivilege(cLP);
                        break;
                    case "bypassuac":
                        _BypassUAC(cLP, hToken);
                        break;
                    case "clear_desktop_acl":
                        _ClearDesktopACL();
                        break;
                    case "clone_token":
                        _CloneToken(remote, processID, command, hToken);
                        break;
                    case "create_token":
                        _CreateToken(cLP, hToken);
                        break;
                    case "delete_driver":
                        _UnInstallDriver(cLP);
                        break;
                    case "detach_filter":
                        Filters.FilterDetach(cLP);
                        break;
                    case "disable_privilege":
                        _AlterPrivilege(cLP, hToken, Winnt.TokenPrivileges.SE_PRIVILEGE_NONE);
                        break;
                    case "enable_privilege":
                        _AlterPrivilege(cLP, hToken, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);
                        break;
                    case "exit":
                        Environment.Exit(0);
                        break;
                    case "find_user_processes":
                        _FindUserProcesses(cLP);
                        break;
                    case "find_user_processes_wmi":
                        _FindUserProcessesWMI(cLP);
                        break;
                    case "getinfo":
                        _Info(cLP, hToken);
                        break;
                    case "getsystem":
                        _GetSystem(cLP, hToken);
                        break;
                    case "get_system":
                        _GetSystem(cLP, hToken);
                        break;
                    case "gettrustedinstaller":
                        _GetTrustedInstaller(cLP, hToken);
                        break;
                    case "get_trustedinstaller":
                        _GetTrustedInstaller(cLP, hToken);
                        break;
                    case "help":
                        _Help(input);
                        break;
                    case "history":
                        console.GetHistory();
                        break;
                    case "info":
                        _Info(cLP, hToken);
                        break;
                    case "install_driver":
                        _InstallDriver(cLP);
                        break;
                    case "list_filters":
                        _ListFilters();
                        break;
                    case "list_filter_instances":
                        _ListFiltersInstances(cLP);
                        break;
                    case "list_privileges":
                        _ListPrivileges(cLP, hToken);
                        break;
                    case "logon_user":
                        _LogonUser(cLP, hToken);
                        break;
                    case "nuke_privileges":
                        _NukePrivileges(cLP, hToken);
                        break;
                    case "pid":
                        Console.WriteLine("[+] Process ID: {0}", Process.GetCurrentProcess().Id);
                        Console.WriteLine("[+] Parent ID:  {0}", Process.GetCurrentProcess().Parent().Id);
                        break;
                    case "remove_privilege":
                        _AlterPrivilege(cLP, hToken, Winnt.TokenPrivileges.SE_PRIVILEGE_REMOVED);
                        break;
                    case "is_critical_process":
                        _IsCriticalProcess(cLP, hProcess);
                        break;
                    case "set_critical_process":
                        _SetCriticalProcess(cLP, hProcess);
                        break;
                    case "reverttoself":
                        Console.WriteLine(advapi32.RevertToSelf() ? "[*] Reverted token to " + WindowsIdentity.GetCurrent().Name : "[-] RevertToSelf failed");
                        break;
                    case "run":
                        _Run(cLP);
                        break;
                    case "runas":
                        _RunAsNetOnly(cLP);
                        break;
                    case "runpowershell":
                        _RunPowerShell(cLP);
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
                    case "start_driver":
                        _StartDriver(cLP);
                        break;
                    case "steal_pipe_token":
                        _StealPipeToken(cLP);
                        break;
                    case "steal_token":
                        _StealToken(cLP, hToken);
                        break;
                    case "tasklist":
                        UserSessions.Tasklist();
                        break;
                    case "terminate":
                        _Terminate(cLP);
                        break;
                    case "unfreeze_token":
                        _UnfreezeToken(cLP);
                        break;
                    case "uninstall_driver":
                        _UnInstallDriver(cLP);
                        break;
                    case "unload_filter":
                        Filters.Unload(cLP);
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
