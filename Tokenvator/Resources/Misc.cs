using System;
using System.IO;
using System.Linq;

using MonkeyWorks.Unmanaged.Libraries;
using Tokenvator.Plugins.Execution;

namespace Tokenvator.Resources
{
    static class Misc
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Finds an exe in command
        ////////////////////////////////////////////////////////////////////////////////
        public static void FindExe(ref string command, out string arguments)
        {
            arguments = "";
            if (command.Contains(" "))
            {
                string[] commandAndArguments = command.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                command = commandAndArguments.First();
                arguments = string.Join(" ", commandAndArguments.Skip(1).Take(commandAndArguments.Length - 1).ToArray());
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Return the full path to binary file
        ////////////////////////////////////////////////////////////////////////////////
        public static bool FindFullPath(string input, out string fullpath)
        {
            fullpath = string.Empty;
            try
            {
                fullpath = Path.GetFullPath(input);
                return true;
            }
            catch (Exception ex)
            {
                if (ex is ArgumentException)
                {
                    //I don't like calling CreateProcess here
                    fullpath = CreateProcess.FindFilePath(input);
                    if (string.IsNullOrEmpty(fullpath))
                    {
                        Console.WriteLine("[-] Unable to locate full binary path");
                        return false;
                    }
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetLsaNtError(string location, uint ntError)
        {
            uint win32Error = advapi32.LsaNtStatusToWinError(ntError);
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception((int)win32Error).Message);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetNtError(string location, uint ntError)
        {
            uint win32Error = ntdll.RtlNtStatusToDosError(ntError);
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0} (0x{1})", new System.ComponentModel.Win32Exception((int)win32Error).Message, ntError.ToString("X4"));
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetWin32Error(string location)
        {
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error()).Message);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Pops an item from the input and returns the item - only used in inital menu
        // Taken from FowlPlay
        ////////////////////////////////////////////////////////////////////////////////
        public static string NextItem(ref string input)
        {
            string option = string.Empty;
            string[] options = input.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            if (options.Length > 1)
            {
                option = options[0];
                input = string.Join(" ", options, 1, options.Length - 1);
            }
            else
            {
                option = input;
            }
            return option.ToLower();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Pops an item from the input and returns the item - only used in inital menu
        // Taken from FowlPlay
        ////////////////////////////////////////////////////////////////////////////////
        public static string NextItemPreserveCase(ref string input)
        {
            string option = string.Empty;
            string[] options = input.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            if (options.Length > 1)
            {
                option = options[0];
                input = string.Join(" ", options, 1, options.Length - 1);
            }
            else
            {
                option = input;
            }
            return option;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // https://stackoverflow.com/questions/16100/convert-a-string-to-an-enum-in-c-sharp
        ////////////////////////////////////////////////////////////////////////////////
        public static T ParseEnum<T>(string value)
        {
            return (T)Enum.Parse(typeof(T), value, true);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Print a struct
        ////////////////////////////////////////////////////////////////////////////////
        public static void PrintStruct<T>(T printMe)
        {
            System.Reflection.FieldInfo[] fields = printMe.GetType().GetFields();
            Console.WriteLine("==========");
            foreach (var xInfo in fields)
            {
                Console.WriteLine("Field    {0}", xInfo.GetValue(printMe).ToString());
            }
            Console.WriteLine("==========");
        }

        //https://stackoverflow.com/questions/1343704/casting-c-sharp-out-parameters
        static bool TryGetTypedValue<TKey, TValue, TActual>(this System.Collections.Generic.IDictionary<TKey, TValue> data, TKey key, out TActual value) where TActual : TValue
        {
            TValue tmp;
            if (data.TryGetValue(key, out tmp))
            {
                value = (TActual)tmp;
                return true;
            }
            value = default(TActual);
            return false;
        }
    }
}
