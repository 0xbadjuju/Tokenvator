using System;
using System.Collections.Generic;
using System.Management;
using System.ServiceProcess;

namespace Tokenvator.Plugins.Execution
{
    sealed class Services
    {
        private ServiceController service;
        private string serviceName;

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public Services(string serviceName)
        {
            this.serviceName = serviceName;
            service = new ServiceController(serviceName);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public bool StartService()
        {
            Console.WriteLine("[*] Starting Service " + serviceName);
            if (service.Status == ServiceControllerStatus.Running)
            {
                return true;
            }
            
            service.Start();
            while (service.Status == ServiceControllerStatus.StartPending || service.Status == ServiceControllerStatus.Stopped)
            {
                System.Threading.Thread.Sleep(1000);
                Console.Write("+");
                service.Refresh();
            }
            Console.Write("\n");
            
            if (service.Status == ServiceControllerStatus.Running)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public bool StopService()
        {
            Console.WriteLine("[+] Stopping Service {0}", serviceName);
            if (service.CanStop)
            {
                service.Stop();
                while (service.Status == ServiceControllerStatus.StopPending)
                {
                    System.Threading.Thread.Sleep(1000);
                    Console.Write("-");
                    service.Refresh();
                }
                Console.Write("\n");

                if (service.Status == ServiceControllerStatus.Stopped)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else if (service.CanPauseAndContinue)
            {
                service.Pause();
                while (service.Status == ServiceControllerStatus.PausePending)
                {
                    System.Threading.Thread.Sleep(1000);
                    Console.Write("-");
                    service.Refresh();
                }
                Console.Write("\n");

                if (service.Status == ServiceControllerStatus.Paused)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                Console.WriteLine("Unable to stop service");
                return false;
            }
        }
    }
}
