using System;

////////////////////////////////////////////////////////////////////////////////
// https://github.com/clymb3r/PowerShell/blob/master/Invoke-TokenManipulation/Invoke-TokenManipulation.ps1
////////////////////////////////////////////////////////////////////////////////
namespace Tokenvator
{
    class Program
    {
        static void Main(string[] args)
        {
            if (0 < args.Length)
            {
                using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
                {
                    using (System.IO.StreamWriter streamWriter = new System.IO.StreamWriter(memoryStream))
                    {
                        using (System.IO.StreamReader streamReader = new System.IO.StreamReader(memoryStream))
                        {
                            string[] commands = string.Join(" ", args).Split(new string[] { ";" }, StringSplitOptions.RemoveEmptyEntries);
                            int offset = 0;
                            foreach (string command in commands)
                            {
                                streamWriter.Write(command.Trim());
                                streamWriter.Flush();
                               
                                memoryStream.Seek(offset, System.IO.SeekOrigin.Begin);
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
}