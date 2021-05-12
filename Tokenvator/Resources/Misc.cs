using System;
using System.Linq;

using MonkeyWorks.Unmanaged.Libraries;

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
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetNtError(string location, uint ntError)
        {
            uint win32Error = ntdll.RtlNtStatusToDosError(ntError);
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception((int)win32Error).Message);
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
    }
}
