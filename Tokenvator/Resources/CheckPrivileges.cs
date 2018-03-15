using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Tokenvator
{
    class CheckPrivileges
    {            
        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetSystem()
        {
            WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
            if (!currentIdentity.IsSystem)
            {
                WindowsPrincipal currentPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());

                Console.WriteLine("Not running as SYSTEM, checking for Administrator access.");
                Console.WriteLine(String.Format("Operating as {0}", WindowsIdentity.GetCurrent().Name));

                if (CheckElevation(currentIdentity.Token))
                {
                    Console.WriteLine("Attempting to elevate to SYSTEM");
                    new Tokens().GetSystem();
                    if (!WindowsIdentity.GetCurrent().IsSystem)
                    {
                        Console.WriteLine("GetSystem Failed");
                        return false;
                    }
                    Console.WriteLine("Running as SYSTEM");
                    Console.WriteLine(" ");
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                Console.WriteLine("Running as SYSTEM");
                return true;
            }
            
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean PrintElevation(IntPtr hToken)
        {
            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(UInt32));
            IntPtr tokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)));
            UInt32 returnLength;

            Boolean result = advapi32.GetTokenInformation(
                hToken,
                Enums._TOKEN_INFORMATION_CLASS.TokenElevationType,
                tokenInformation,
                tokenInformationLength,
                out returnLength
            );

            switch ((Enums.TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(tokenInformation))
            {
                case Enums.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    Console.WriteLine("TokenElevationTypeDefault");
                    Console.WriteLine("Token: Not Split");
                    Console.WriteLine("ProcessIntegrity: Medium/Low");
                    return false;
                case Enums.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    Console.WriteLine("TokenElevationTypeFull");
                    Console.WriteLine("Token: Split");
                    Console.WriteLine("ProcessIntegrity: High");
                    return true;
                case Enums.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    Console.WriteLine("TokenElevationTypeLimited");
                    Console.WriteLine("Token: Split - ProcessIntegrity: Medium/Low");
                    Console.WriteLine("Hint: Try to Bypass UAC");
                    return false;
                default:
                    Console.WriteLine("Unknown integrity");
                    Console.WriteLine("Trying anyway");
                    return true;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean CheckElevation(IntPtr hToken)
        {
            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(UInt32));
            IntPtr tokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)));
            UInt32 returnLength;

            Boolean result = advapi32.GetTokenInformation(
                hToken,
                Enums._TOKEN_INFORMATION_CLASS.TokenElevationType,
                tokenInformation,
                tokenInformationLength,
                out returnLength
            );

            switch ((Enums.TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(tokenInformation))
            {
                case Enums.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:;
                    return false;
                case Enums.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    return true;
                case Enums.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    return false;
                default:
                    return true;
            }
        }
    }
}