using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;

using Tokenvator.Resources;

namespace Tokenvator
{

    ////////////////////////////////////////////////////////////////////////////////
    // This is mostly pulled from a stack exchange question
    ////////////////////////////////////////////////////////////////////////////////
    class TabComplete
    {        
        private static Assembly assembly = Assembly.GetExecutingAssembly();

        private List<string> scrollback = new List<string>();
        private int scrollbackPosition = 0;

        private List<string> options = new List<string>();

        private string context;

        private readonly List<string> flags = new List<string>()
        { 
            "All", "Command", "Filter", "Force", "Groups", "Impersonation", "Password", "Path", "Privilege", "Process", "ServiceName", "State", "Thread", "Username"        
        };


        ////////////////////////////////////////////////////////////////////////////////
        // Default constructor
        ////////////////////////////////////////////////////////////////////////////////
        public TabComplete(string context, string[,] menu)
        {
            this.context = context;

            for (int i = 0; i < menu.GetLength(0); i++)
            {
                options.Add(menu[i,0]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Get input history
        ////////////////////////////////////////////////////////////////////////////////
        public void GetHistory()
        {
            for (int i = 0; i < scrollbackPosition; i++)
            {
                try
                {
                    Console.WriteLine("{0} - {1}", i, scrollback[i]);
                }
                catch { continue; }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Get console input
        ////////////////////////////////////////////////////////////////////////////////
        public string ReadLine()
        {
            StringBuilder stringBuilder = new StringBuilder();
            ConsoleKey hold = ConsoleKey.EraseEndOfFile;
            while (true)
            {
                ConsoleKeyInfo input = Console.ReadKey(true);
                switch (input.Key)
                {
                    case ConsoleKey.Enter:
                        Console.WriteLine();
                        scrollback.Add(stringBuilder.ToString());
                        //scrollbackPosition++;
                        scrollbackPosition = scrollback.Count;
                        return stringBuilder.ToString();
                    case ConsoleKey.Tab:
                        if (hold == input.Key)
                        {
                            TabInput(stringBuilder, true);
                        }
                        else
                        {
                            TabInput(stringBuilder, false);
                        }
                        break;
                    case ConsoleKey.UpArrow:
                        if (scrollbackPosition > 0 && scrollback.Count > 0)
                        {
                            stringBuilder.Remove(0, stringBuilder.Length);
                            stringBuilder.Append(scrollback[--scrollbackPosition]);
                        }
                        break;
                    case ConsoleKey.DownArrow:
                        if (scrollbackPosition + 1 < scrollback.Count)
                        {
                            stringBuilder.Remove(0, stringBuilder.Length);
                            stringBuilder.Append(scrollback[++scrollbackPosition]);
                        }
                        else
                        {
                            stringBuilder.Remove(0, stringBuilder.Length);
                        }
                        break;
                    case ConsoleKey.LeftArrow:
                        if (Console.CursorLeft - context.Length - 1 >= 0)
                            Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        continue;
                    case ConsoleKey.RightArrow:
                        if (Console.CursorLeft < context.Length + stringBuilder.Length)
                            Console.SetCursorPosition(Console.CursorLeft + 1, Console.CursorTop);
                        continue;
                    case ConsoleKey.Escape:
                        stringBuilder.Remove(0, stringBuilder.Length);
                        break;
                    default:
                        if (KeyInput(stringBuilder, input))
                        {
                            break;
                        }
                        else
                        {
                            continue;
                        }
                }
                ResetLine();
                Console.Write(stringBuilder.ToString());
                hold = input.Key;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Process tab inputs and autocomplete
        ////////////////////////////////////////////////////////////////////////////////
        private void TabInput(StringBuilder stringBuilder, bool doubleTab)
        {
            StringBuilder tempBuilder = new StringBuilder(); ;
            string input = stringBuilder.ToString();

            if (doubleTab)
            {
                //Console.WriteLine("\n" + String.Join("\n", options.ToArray()) + "\n");
                for (int i = 0; i < MainLoop.options.GetLength(0); i++)
                {
                    if (string.Equals(input.Trim(), MainLoop.options[i, 0], StringComparison.InvariantCultureIgnoreCase))
                    {
                        Console.WriteLine();
                        Console.WriteLine("{0,-25}{1,-20}{2,-20}", "Name", "Optional", "Required");
                        Console.WriteLine("{0,-25}{1,-20}{2,-20}", "----", "--------", "--------");
                        Console.WriteLine("{0,-25}{1,-20}{2,-20}", MainLoop.options[i, 0], MainLoop.options[i, 1], MainLoop.options[i, 2]);
                        Console.WriteLine();
                    }
                }
                return;
            }

            string candidate = options.FirstOrDefault(i => i != input && i.StartsWith(input, true, System.Globalization.CultureInfo.InvariantCulture));

            if (!string.IsNullOrEmpty(candidate))
            {
                tempBuilder.Append(candidate);
                ResetLine();
                stringBuilder.Remove(0, stringBuilder.Length);
                stringBuilder.Append(tempBuilder.ToString());
            }

            //Autocomplete Flags
            string[] split = input.Split(new string[] { "/"}, StringSplitOptions.None);
            string last = split.Last();
            if (1 < split.Length && !last.Contains(":"))
            {
                candidate = flags.FirstOrDefault(i => i != last && i.StartsWith(last, true, System.Globalization.CultureInfo.InvariantCulture));
                string j = string.Join("/", split.Take(split.Length - 1));
                ResetLine();
                stringBuilder.Clear();
                stringBuilder.Append(j + "/" + candidate);
                return;
            }

            //Autocomplete Data
            last = input.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries).Last();
            split = input.Split(new string[] { "/", ":" }, StringSplitOptions.None);
            if (1 < split.Length)
            {
                string flag = split[split.Length - 2].ToLower();
                string item = split.Last();

                switch (flag)
                {
                    case "privilege":
                        candidate = CommandLineParsing.privileges.FirstOrDefault(i => i != item && i.StartsWith(item, true, System.Globalization.CultureInfo.InvariantCulture));
                        string[] j = input.Split(new string[] { ":" }, StringSplitOptions.None);
                        string k = string.Join(":", j.Take(j.Length - 1));
                        ResetLine();
                        stringBuilder.Clear();
                        stringBuilder.Append(string.Format("{0}:{1}", k, candidate));
                        return;
                    default:
                        break;
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Clear the input line
        ////////////////////////////////////////////////////////////////////////////////
        private void ResetLine()
        {
            Console.SetCursorPosition(context.Length, Console.CursorTop);
            //This is needed for backspaces
            Console.Write(new string(' ', Console.WindowWidth/2));
            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(context);
            Console.SetCursorPosition(context.Length, Console.CursorTop);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Read key input
        ////////////////////////////////////////////////////////////////////////////////
        private bool KeyInput(StringBuilder stringBuilder, ConsoleKeyInfo keyDown)
        {
            int position = Console.CursorLeft;
            if (ConsoleKey.Backspace == keyDown.Key)
            {
                try
                {
                    if (Console.CursorLeft - context.Length - 1 >= 0)
                    {
                        stringBuilder.Remove(Console.CursorLeft - context.Length - 1, 1);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                ResetLine();
                Console.Write(stringBuilder.ToString());
                if (Console.CursorLeft - context.Length - 1 >= 0)
                {
                    Console.SetCursorPosition(position - 1, Console.CursorTop);
                }
                return false;
            }

            if (ConsoleKey.Delete == keyDown.Key)
            {
                try
                {
                    if (position - context.Length + 1 < stringBuilder.Length)
                        stringBuilder.Remove(position - context.Length + 1, 1);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                ResetLine();
                Console.Write(stringBuilder.ToString());
                Console.SetCursorPosition(position, Console.CursorTop);
                return false;
            }

            char key = keyDown.KeyChar;
            if (Console.CursorLeft < (stringBuilder.Length + context.Length))
            {
                try
                {
                    stringBuilder.Insert(position - context.Length, key);
                }
                catch { }
                ResetLine();
                Console.Write(stringBuilder.ToString());
                Console.SetCursorPosition(position + 1, Console.CursorTop);
                return false;
            }
            else
            {
                stringBuilder.Append(key);
                return true;
            }
        }
    }
}