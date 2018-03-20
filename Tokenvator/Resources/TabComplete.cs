using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;

namespace Tokenvator
{

    ////////////////////////////////////////////////////////////////////////////////
    // This is mostly pulled from a stack exchange question
    ////////////////////////////////////////////////////////////////////////////////
    class TabComplete
    {        
        private static Assembly assembly = Assembly.GetExecutingAssembly();
        private List<String> namespaces;

        private List<String> scrollback = new List<string>();
        private Int32 scrollbackPosition = 0;

        private List<String> options = new List<String>();

        private String context;

        ////////////////////////////////////////////////////////////////////////////////
        // Default constructor
        ////////////////////////////////////////////////////////////////////////////////
        public TabComplete(String context, String[,] menu)
        {
            this.context = context;

            for (Int32 i = 0; i < menu.GetLength(0); i++)
            {
                options.Add((String)menu[i,0]);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Get console input
        ////////////////////////////////////////////////////////////////////////////////
        public String ReadLine()
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
                            stringBuilder.Append(scrollback[scrollbackPosition--]);
                        }
                        break;
                    case ConsoleKey.DownArrow:
                        if (scrollbackPosition + 1 < scrollback.Count)
                        {
                            stringBuilder.Remove(0, stringBuilder.Length);
                            stringBuilder.Append(scrollback[scrollbackPosition++]);
                        }
                        break;
                    case ConsoleKey.LeftArrow:
                        Console.SetCursorPosition(Console.CursorLeft - 1,Console.CursorTop);
                        break;
                    case ConsoleKey.RightArrow:
                        Console.SetCursorPosition(Console.CursorLeft + 1, Console.CursorTop);
                        break;
                    default:
                        KeyInput(stringBuilder, input);
                        break;
                }
                ResetLine();
                Console.Write(stringBuilder.ToString());
                hold = input.Key;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Process tab inputs and autocomplete
        ////////////////////////////////////////////////////////////////////////////////
        private void TabInput(StringBuilder stringBuilder, Boolean doubleTab)
        {
            StringBuilder tempBuilder = new StringBuilder(); ;
            String input = stringBuilder.ToString();

            if (doubleTab)
            {
                Console.WriteLine("\n" + String.Join(" ", options.ToArray()) + "\n");
                return;
            }

            String candidate = options.FirstOrDefault(i => i != input && i.StartsWith(input, true, System.Globalization.CultureInfo.InvariantCulture));


            if (string.IsNullOrEmpty(candidate))
            {
                return;
            }
            tempBuilder.Append(candidate);

            ResetLine();
            stringBuilder.Remove(0, stringBuilder.Length);
            stringBuilder.Append(tempBuilder.ToString());
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Clear the input line
        ////////////////////////////////////////////////////////////////////////////////
        private void ResetLine()
        {
            Console.SetCursorPosition(context.Length, Console.CursorTop);
            //This is needed for backspaces
            Console.Write(new String(' ', Console.WindowWidth/2));
            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(context);
            Console.SetCursorPosition(context.Length, Console.CursorTop);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Read key input
        ////////////////////////////////////////////////////////////////////////////////
        private void KeyInput(StringBuilder stringBuilder, ConsoleKeyInfo keyDown)
        {
            String input = stringBuilder.ToString();
            if (ConsoleKey.Backspace == keyDown.Key && 0 <= input.Length)
            {
                try
                {
                    stringBuilder.Remove(stringBuilder.Length - 1, 1);
                    ResetLine();
                    input = input.Remove(input.Length - 1);
                }
                catch (IndexOutOfRangeException)
                {

                }
                catch (ArgumentOutOfRangeException)
                {

                }
                Console.Write(input);
            }
            else
            {
                Char key = keyDown.KeyChar;
                stringBuilder.Append(key);
            }
        }
    }
}