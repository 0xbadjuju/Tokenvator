using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

using Tokenvator.Resources;

namespace Tokenvator.Plugins.Execution
{
    sealed class PSExec : IDisposable
    {
        private readonly string serviceName;
        private IntPtr hServiceManager;
        private IntPtr hSCObject;

        private bool disposed;

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public PSExec(string serviceName)
        {
            this.serviceName = serviceName;
            Console.WriteLine("[*] Using Service Name {0}", serviceName);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public PSExec()
        {
            serviceName = GenerateUuid(12);
            Console.WriteLine("[*] Using Service Name {0}", serviceName);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        ~PSExec()
        {
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            if (!disposed)
            {
                Delete();
            }
            disposed = true;
            if (IntPtr.Zero != hSCObject)
            {
                advapi32.CloseServiceHandle(hSCObject);
            }

            if (IntPtr.Zero != hServiceManager)
            {
                kernel32.CloseHandle(hServiceManager);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal bool Connect(string machineName)
        {
            Console.WriteLine("[*] Connecting to {0}", machineName);

            hServiceManager = advapi32.OpenSCManager(
                machineName, 
                null, 
                Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CONNECT | Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CREATE_SERVICE
            );

            if (IntPtr.Zero == hServiceManager)
            {
                Console.WriteLine("[-] Failed to connect service controller {0}", machineName);
                Misc.GetWin32Error("OpenSCManager");
                disposed = true;
                return false;
            }

            Console.WriteLine("[+] Connected to {0}", machineName);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a service
        ////////////////////////////////////////////////////////////////////////////////
        internal bool Create(string lpBinaryPathName)
        {
            Console.WriteLine("[*] Creating service {0}", serviceName);
            //Console.WriteLine(lpBinaryPathName);
            IntPtr hSCObject = advapi32.CreateService(
                hServiceManager,
                serviceName, serviceName,
                Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS,
                Winsvc.dwServiceType.SERVICE_WIN32_OWN_PROCESS,
                Winsvc.dwStartType.SERVICE_DEMAND_START,
                Winsvc.dwErrorControl.SERVICE_ERROR_IGNORE,
                lpBinaryPathName,
                string.Empty, null, string.Empty, null, null
            );

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to create service");
                Console.WriteLine(Marshal.GetLastWin32Error());
                disposed = true;
                return false;
            }

            advapi32.CloseServiceHandle(hSCObject);
            Console.WriteLine("[+] Created service {0}", serviceName);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a service
        ////////////////////////////////////////////////////////////////////////////////
        internal bool CreateDriver(string source, bool overwrite)
        {
            Console.WriteLine("[*] Creating service {0}", serviceName);

            string destination = string.Format("{0}\\System32\\drivers\\", Environment.GetEnvironmentVariable("SystemRoot"));

            string filename = Path.GetFileName(source);

            destination += filename;

            Console.WriteLine("[*] Copying file from {0} to {1}", source, destination);

            File.Copy(source, destination, overwrite);

            IntPtr hSCObject = advapi32.CreateService(
                hServiceManager,
                serviceName, serviceName,
                Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS,
                Winsvc.dwServiceType.SERVICE_KERNEL_DRIVER,
                Winsvc.dwStartType.SERVICE_DEMAND_START,
                Winsvc.dwErrorControl.SERVICE_ERROR_NORMAL,
                destination,
                string.Empty, null, string.Empty, null, null
            );

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to create service");
                Misc.GetWin32Error("CreateService");
                disposed = true;
                return false;
            }

            advapi32.CloseServiceHandle(hSCObject);
            Console.WriteLine("[+] Created service {0}", serviceName);
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        // Opens a handle to a service
        ///////////////////////////////////////////////////////////////////////////////
        internal bool Open()
        {
            hSCObject = advapi32.OpenService(
                hServiceManager, 
                serviceName, 
                Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS
            );

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to open service");
                Misc.GetWin32Error("Open");
                return false;
            }

            Console.WriteLine("[+] Opened service");
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        // Starts the service, if there is a start timeout error, return true
        ///////////////////////////////////////////////////////////////////////////////
        internal bool Start()
        {
            if (!advapi32.StartService(hSCObject, 0, null))
            {
                int error = Marshal.GetLastWin32Error();
                if (1053 != error)
                {
                    Console.WriteLine("[-] Failed to start service");
                    Misc.GetWin32Error("StartService");
                    return false;
                }
            }
            Console.WriteLine("[+] Started Service");
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        // Stops the service, if service is already stopped returns true
        ///////////////////////////////////////////////////////////////////////////////
        internal bool Stop()
        {
            Winsvc._SERVICE_STATUS serviceStatus;
            IntPtr hControlService = advapi32.ControlService(hSCObject, Winsvc.dwControl.SERVICE_CONTROL_STOP, out serviceStatus);

            if (IntPtr.Zero == hControlService)
            {
                int error = Marshal.GetLastWin32Error();
                if (1062 != error)
                {
                    Console.WriteLine("[-] Failed to stop service");
                    Console.WriteLine(new System.ComponentModel.Win32Exception(error).Message);
                    return false;
                }
            }
            Console.WriteLine("[+] Stopped Service");
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Deletes the service
        ////////////////////////////////////////////////////////////////////////////////
        internal bool Delete()
        {
            if (!advapi32.DeleteService(hSCObject))
            {
                Console.WriteLine("[-] Failed to delete service");
                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            Console.WriteLine("[+] Deleted service");
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal static string GenerateUuid(int length)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}