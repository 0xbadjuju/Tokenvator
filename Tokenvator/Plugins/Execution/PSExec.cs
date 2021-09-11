using System;
using System.IO;
using System.Runtime.InteropServices;

using DInvoke.DynamicInvoke;

using MonkeyWorks.Unmanaged.Headers;
//using MonkeyWorks.Unmanaged.Libraries;

using Tokenvator.Resources;

namespace Tokenvator.Plugins.Execution
{
    using MonkeyWorks = MonkeyWorks.Unmanaged.Libraries.DInvoke;

    sealed class PSExec : IDisposable
    {
        private readonly string serviceName;
        private IntPtr hServiceManager;
        private IntPtr hSCObject;

        private bool disposed;

        private IntPtr hadvapi32;

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public PSExec(string serviceName)
        {
            this.serviceName = serviceName;
            Console.WriteLine("[*] Using Service Name {0}", serviceName);
            hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public PSExec()
        {
            serviceName = Misc.GenerateUuid(12);
            Console.WriteLine("[*] Using Service Name {0}", serviceName);
            hadvapi32 = Generic.GetPebLdrModuleEntry("advapi32.dll");
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        ~PSExec()
        {
            if (!disposed)
            {
                Dispose();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Closes the handles that were opened to the service and service controller
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="machineName"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.CloseServiceHandle(hSCObject);
            // kernel32.CloseHandle(hServiceManager);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hCloseServiceHandle = Generic.GetExportAddress(hadvapi32, "CloseServiceHandle");
            MonkeyWorks.advapi32.CloseServiceHandle fCloseServiceHandle = (MonkeyWorks.advapi32.CloseServiceHandle)Marshal.GetDelegateForFunctionPointer(hCloseServiceHandle, typeof(MonkeyWorks.advapi32.CloseServiceHandle));

            try
            {
                fCloseServiceHandle(hSCObject);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CloseServiceHandle Generated an Exception");
                Console.WriteLine(ex.Message);
            }

            try
            {
                fCloseServiceHandle(hServiceManager);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CloseServiceHandle Generated an Exception");
                Console.WriteLine(ex.Message);
            }

            disposed = true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Connects to the service controller manager - can be used against a remote system
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="machineName"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool Connect(string machineName)
        {
            Console.WriteLine("[*] Connecting to {0}", machineName);

            ////////////////////////////////////////////////////////////////////////////////
            // hServiceManager = advapi32.OpenSCManager(machineName, null, Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CONNECT | Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CREATE_SERVICE);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hOpenSCManagerW = Generic.GetExportAddress(hadvapi32, "OpenSCManagerW");
            MonkeyWorks.advapi32.OpenSCManagerW fOpenSCManagerW = (MonkeyWorks.advapi32.OpenSCManagerW)Marshal.GetDelegateForFunctionPointer(hOpenSCManagerW, typeof(MonkeyWorks.advapi32.OpenSCManagerW));

            try
            {
                hServiceManager = fOpenSCManagerW(
                    machineName,
                    null,
                    Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CONNECT
                    | Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CREATE_SERVICE
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] OpenSCManagerW Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }

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
        /// <summary>
        /// Creates a generic standalone service
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="lpBinaryPathName"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool Create(string lpBinaryPathName)
        {
            Console.WriteLine("[*] Creating service {0}", serviceName);

            ////////////////////////////////////////////////////////////////////////////////
            // IntPtr hSCObject = advapi32.CreateService(hServiceManager,serviceName, serviceName,Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS,Winsvc.dwServiceType.SERVICE_WIN32_OWN_PROCESS,Winsvc.dwStartType.SERVICE_DEMAND_START,Winsvc.dwErrorControl.SERVICE_ERROR_IGNORE,lpBinaryPathName, string.Empty, null, string.Empty, null, null);            
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hCreateServiceW = Generic.GetExportAddress(hadvapi32, "CreateServiceW");
            MonkeyWorks.advapi32.CreateServiceW fCreateServiceW = (MonkeyWorks.advapi32.CreateServiceW)Marshal.GetDelegateForFunctionPointer(hCreateServiceW, typeof(MonkeyWorks.advapi32.CreateServiceW));
            
            try
            {
                hSCObject = fCreateServiceW(
                    hServiceManager,
                    serviceName, serviceName,
                    Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS,
                    Winsvc.dwServiceType.SERVICE_WIN32_OWN_PROCESS,
                    Winsvc.dwStartType.SERVICE_DEMAND_START,
                    Winsvc.dwErrorControl.SERVICE_ERROR_IGNORE,
                    lpBinaryPathName,
                    string.Empty, null, string.Empty, null, null
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CreateServiceW Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to create service");
                Misc.GetWin32Error("CreateServiceW");
                return false;
            }

            Console.WriteLine("[+] Created service {0}", serviceName);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Creates a service to execute a kernel driver
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <param name="source"></param>
        /// <param name="overwrite"></param>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        public bool CreateDriver(string source, bool overwrite)
        {
            Console.WriteLine("[*] Creating service {0}", serviceName);

            ////////////////////////////////////////////////////////////////////////////////
            // Driver file needs to copied to a specific location
            ////////////////////////////////////////////////////////////////////////////////
            string destination = string.Format("{0}\\System32\\drivers\\", Environment.GetEnvironmentVariable("SystemRoot"));
            string filename = Path.GetFileName(source);
            destination += filename;
            Console.WriteLine("[*] Copying file from {0} to {1}", source, destination);
            File.Copy(source, destination, overwrite);

            ////////////////////////////////////////////////////////////////////////////////
            // advapi32.CreateService(hServiceManager, serviceName, serviceName, Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS, Winsvc.dwServiceType.SERVICE_KERNEL_DRIVER, Winsvc.dwStartType.SERVICE_DEMAND_START, Winsvc.dwErrorControl.SERVICE_ERROR_NORMAL, destination, string.Empty, null, string.Empty, null, null);
            ////////////////////////////////////////////////////////////////////////////////
            IntPtr hCreateServiceW = Generic.GetExportAddress(hadvapi32, "CreateServiceW");
            MonkeyWorks.advapi32.CreateServiceW fCreateServiceW = (MonkeyWorks.advapi32.CreateServiceW)Marshal.GetDelegateForFunctionPointer(hCreateServiceW, typeof(MonkeyWorks.advapi32.CreateServiceW));

            try
            {
                hSCObject = fCreateServiceW(
                    hServiceManager,
                    serviceName, serviceName,
                    Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS,
                    Winsvc.dwServiceType.SERVICE_KERNEL_DRIVER,
                    Winsvc.dwStartType.SERVICE_DEMAND_START,
                    Winsvc.dwErrorControl.SERVICE_ERROR_NORMAL,
                    destination,
                    string.Empty, null, string.Empty, null, null
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] CreateServiceW Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to create service");
                Misc.GetWin32Error("CreateService");
                return false;
            }

            Console.WriteLine("[+] Created service {0}", serviceName);
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Opens a handle to a service
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <returns></returns>
        ///////////////////////////////////////////////////////////////////////////////
        public bool Open()
        {
            ///////////////////////////////////////////////////////////////////////////////
            // advapi32.OpenService(hServiceManager, serviceName, Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS);
            ///////////////////////////////////////////////////////////////////////////////
            IntPtr hOpenServiceW = Generic.GetExportAddress(hadvapi32, "OpenServiceW");
            MonkeyWorks.advapi32.OpenServiceW fOpenServiceW = (MonkeyWorks.advapi32.OpenServiceW)Marshal.GetDelegateForFunctionPointer(hOpenServiceW, typeof(MonkeyWorks.advapi32.OpenServiceW));

            try
            {
                hSCObject = fOpenServiceW(
                    hServiceManager,
                    serviceName,
                    Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] OpenServiceW Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to open service");
                Misc.GetWin32Error("OpenServiceW");
                return false;
            }

            Console.WriteLine("[+] Opened service");
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Starts the service, if there is a start timeout error, return true
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <returns></returns>
        ///////////////////////////////////////////////////////////////////////////////
        internal bool Start()
        {
            ///////////////////////////////////////////////////////////////////////////////
            // advapi32.StartService(hSCObject, 0, null)
            ///////////////////////////////////////////////////////////////////////////////
            IntPtr hStartServiceW = Generic.GetExportAddress(hadvapi32, "StartServiceW");
            MonkeyWorks.advapi32.StartServiceW fStartServiceW = (MonkeyWorks.advapi32.StartServiceW)Marshal.GetDelegateForFunctionPointer(hStartServiceW, typeof(MonkeyWorks.advapi32.StartServiceW));

            bool retVal = false;
            try
            {
                retVal = fStartServiceW(hSCObject, 0, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] StartServiceW Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }

            if (!retVal)
            {
                int error = Marshal.GetLastWin32Error();
                if (1053 != error)
                {
                    Console.WriteLine("[-] Failed to start service");
                    Misc.GetWin32Error("StartServiceW");
                    return false;
                }
            }
            Console.WriteLine("[+] Started Service");
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Stops the service, if service is already stopped returns true
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <returns></returns>
        ///////////////////////////////////////////////////////////////////////////////
        internal bool Stop()
        {
            ///////////////////////////////////////////////////////////////////////////////
            // advapi32.ControlService(hSCObject, Winsvc.dwControl.SERVICE_CONTROL_STOP, out serviceStatus);
            ///////////////////////////////////////////////////////////////////////////////
            IntPtr hControlService = Generic.GetExportAddress(hadvapi32, "ControlService");
            MonkeyWorks.advapi32.ControlService fControlService = (MonkeyWorks.advapi32.ControlService)Marshal.GetDelegateForFunctionPointer(hControlService, typeof(MonkeyWorks.advapi32.ControlService));

            Winsvc._SERVICE_STATUS serviceStatus = new Winsvc._SERVICE_STATUS();;

            bool retVal = false;
            try
            {
                retVal = fControlService(hSCObject, Winsvc.dwControl.SERVICE_CONTROL_STOP, ref serviceStatus);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ControlService Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }

            if (!retVal)
            {
                int error = Marshal.GetLastWin32Error();
                if (1062 != error)
                {
                    Console.WriteLine("[-] Failed to stop service");
                    Misc.GetWin32Error("ControlService");
                    return false;
                }
            }

            Console.WriteLine("[+] Stopped Service");
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        /// Deletes the service
        /// Converted to GetPebLdrModuleEntry/GetExportAddress
        /// </summary>
        /// <returns></returns>
        ////////////////////////////////////////////////////////////////////////////////
        internal bool Delete()
        {
            ///////////////////////////////////////////////////////////////////////////////
            // advapi32.DeleteService(hSCObject)
            ///////////////////////////////////////////////////////////////////////////////
            IntPtr hDeleteService = Generic.GetExportAddress(hadvapi32, "DeleteService");
            MonkeyWorks.advapi32.DeleteService fDeleteService = (MonkeyWorks.advapi32.DeleteService)Marshal.GetDelegateForFunctionPointer(hDeleteService, typeof(MonkeyWorks.advapi32.DeleteService));

            bool retVal = false;
            try
            {
                retVal = fDeleteService(hSCObject);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] DeleteService Generated an Exception");
                Console.WriteLine(ex.Message);
                return false;
            }


            if (!retVal)
            {
                Misc.GetWin32Error("DeleteService");
                return false;
            }
            Console.WriteLine("[+] Deleted service");
            return true;
        }
    }
}