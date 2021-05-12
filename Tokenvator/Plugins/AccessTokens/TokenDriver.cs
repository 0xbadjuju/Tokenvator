using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

using Tokenvator.Resources;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator.Plugins.AccessTokens
{
    class TokenDriver : IDisposable
    {
        internal enum PRIVILEGES : ulong
        {
            //1000000000000000000000000000000000000 - 36
            SeDelegateSessionUserImpersonatePrivilege = 0x1000000000,
            //0100000000000000000000000000000000000 - 35
            SeCreateSymbolicLinkPrivilege = 0x800000000,
            //0010000000000000000000000000000000000 - 34
            SeTimeZonePrivilege = 0x400000000,
            //0001000000000000000000000000000000000 - 33
            SeIncreaseWorkingSetPrivilege = 0x200000000,
            //0000100000000000000000000000000000000 - 32
            SeRelabelPrivilege = 0x100000000,
            //0000010000000000000000000000000000000 - 31
            SeTrustedCredManAccessPrivilege = 0x80000000,
            //0000001000000000000000000000000000000 - 30
            SeCreateGlobalPrivilege = 0x40000000,
            //0000000100000000000000000000000000000 - 29
            SeImpersonatePrivilege = 0x20000000,
            //0000000010000000000000000000000000000 - 28
            SeManageVolumePrivilege = 0x10000000,
            //0000000001000000000000000000000000000 - 27
            SeEnableDelegationPrivilege = 0x8000000,
            //0000000000100000000000000000000000000 - 26
            SeSyncAgentPrivilege = 0x4000000,
            //0000000000010000000000000000000000000 - 25
            SeUndockPrivilege = 0x2000000,
            //0000000000001000000000000000000000000 - 24
            SeRemoteShutdownPrivilege = 0x1000000,
            //0000000000000100000000000000000000000 - 23
            SeChangeNotifyPrivilege = 0x800000,
            //0000000000000010000000000000000000000 - 22
            SeSystemEnvironmentPrivilege = 0x400000,
            //0000000000000001000000000000000000000 - 21
            SeAuditPrivilege = 0x200000,
            //0000000000000000100000000000000000000 - 20
            SeDebugPrivilege = 0x100000,
            //0000000000000000010000000000000000000 - 19
            SeShutdownPrivilege = 0x80000,
            //0000000000000000001000000000000000000 - 18
            SeRestorePrivilege = 0x40000,
            //0000000000000000000100000000000000000 - 17
            SeBackupPrivilege = 0x20000,
            //0000000000000000000010000000000000000 - 16
            SeCreatePermanentPrivilege = 0x10000,
            //0000000000000000000001000000000000000 - 15
            SeCreatePagefilePrivilege = 0x8000,
            //0000000000000000000000100000000000000 - 14
            SeIncreaseBasePriorityPrivilege = 0x4000,
            //0000000000000000000000010000000000000 - 13
            SeProfileSingleProcessPrivilege = 0x2000,
            //0000000000000000000000001000000000000 - 12
            SeSystemtimePrivilege = 0x1000,
            //0000000000000000000000000100000000000 - 11
            SeSystemProfilePrivilege = 0x800,
            //0000000000000000000000000010000000000 - 10
            SeLoadDriverPrivilege = 0x400,
            //0000000000000000000000000001000000000 - 09
            SeTakeOwnershipPrivilege = 0x200,
            //0000000000000000000000000000100000000 - 08
            SeSecurityPrivilege = 0x100,
            //0000000000000000000000000000010000000 - 07
            SeTcbPrivilege = 0x80,                      //This is off
            //0000000000000000000000000000001000000 - 06
            SeUnsolicitedInputPrivilege = 0x40,
            //0000000000000000000000000000000100000 - 05
            SeIncreaseQuotaPrivilege = 0x20,
            //0000000000000000000000000000000010000 - 04
            SeLockMemoryPrivilege = 0x10,
            //0000000000000000000000000000000001000 - 03
            SeAssignPrimaryTokenPrivilege = 0x8,
            //0000000000000000000000000000000000100 - 02
            SeCreateTokenPrivilege = 0x4
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PRIVILEGE_DATA
        {
            public uint ProcessID;
            public PRIVILEGES Privilege;
        };

        [Flags]
        private enum SHARE_MODE : uint
        {
            FILE_SHARE_LOCKED = 0x00000000,
            FILE_SHARE_READ = 0x00000001,
            FILE_SHARE_WRITE = 0x00000002,
            FILE_SHARE_DELETE = 0x00000004,
        }

        [Flags]
        private enum CREATION_DISPOSITION
        {
            CREATE_NEW = 1,
            CREATE_ALWAYS = 2,
            OPEN_EXISTING = 3,
            OPEN_ALWAYS = 4,
            TRUNCATE_EXISTING = 5,
        }

        [Flags]
        private enum FILE_ATTRIBUTES : uint
        {
            FILE_ATTRIBUTE_ARCHIVE = 0x20,
            FILE_ATTRIBUTE_ENCRYPTED = 0x4000,
            FILE_ATTRIBUTE_HIDDEN = 0x2,
            FILE_ATTRIBUTE_NORMAL = 0x80,
            FILE_ATTRIBUTE_OFFLINE = 0x1000,
            FILE_ATTRIBUTE_READONLY = 0x1,
            FILE_ATTRIBUTE_SYSTEM = 0x4,
            FILE_ATTRIBUTE_TEMPORARY = 0x100,
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000,
            FILE_FLAG_DELETE_ON_CLOSE = 0x04000000,
            FILE_FLAG_NO_BUFFERING = 0x20000000,
            FILE_FLAG_OPEN_NO_RECALL = 0x00100000,
            FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000,
            FILE_FLAG_OVERLAPPED = 0x40000000,
            FILE_FLAG_POSIX_SEMANTICS = 0x0100000,
            FILE_FLAG_RANDOM_ACCESS = 0x10000000,
            FILE_FLAG_SESSION_AWARE = 0x00800000,
            FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000,
            FILE_FLAG_WRITE_THROUGH = 0x80000000,
        }      
   
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName, 
            Winnt.ACCESS_MASK dwDesiredAccess,
            SHARE_MODE dwShareMode, 
            IntPtr lpSecurityAttributes,
            CREATION_DISPOSITION dwCreationDisposition,
            FILE_ATTRIBUTES dwFlagsAndAttributes, 
            IntPtr hTemplateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            ref uint lpBytesReturned, 
            IntPtr lpOverlapped
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtLoadDriver(string DriverServiceName);

        [Flags]
        public enum DeviceType : uint
        {
            FILE_DEVICE_BEEP = 0x00000001,
            FILE_DEVICE_CD_ROM = 0x00000002,
            FILE_DEVICE_CD_ROM_FILE_SYSTEM = 0x00000003,
            FILE_DEVICE_CONTROLLER = 0x00000004,
            FILE_DEVICE_DATALINK = 0x00000005,
            FILE_DEVICE_DFS = 0x00000006,
            FILE_DEVICE_DISK = 0x00000007,
            FILE_DEVICE_DISK_FILE_SYSTEM = 0x00000008,
            FILE_DEVICE_FILE_SYSTEM = 0x00000009,
            FILE_DEVICE_INPORT_PORT = 0x0000000a,
            FILE_DEVICE_KEYBOARD = 0x0000000b,
            FILE_DEVICE_MAILSLOT = 0x0000000c,
            FILE_DEVICE_MIDI_IN = 0x0000000d,
            FILE_DEVICE_MIDI_OUT = 0x0000000e,
            FILE_DEVICE_MOUSE = 0x0000000f,
            FILE_DEVICE_MULTI_UNC_PROVIDER = 0x00000010,
            FILE_DEVICE_NAMED_PIPE = 0x00000011,
            FILE_DEVICE_NETWORK = 0x00000012,
            FILE_DEVICE_NETWORK_BROWSER = 0x00000013,
            FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x00000014,
            FILE_DEVICE_NULL = 0x00000015,
            FILE_DEVICE_PARALLEL_PORT = 0x00000016,
            FILE_DEVICE_PHYSICAL_NETCARD = 0x00000017,
            FILE_DEVICE_PRINTER = 0x00000018,
            FILE_DEVICE_SCANNER = 0x00000019,
            FILE_DEVICE_SERIAL_MOUSE_PORT = 0x0000001a,
            FILE_DEVICE_SERIAL_PORT = 0x0000001b,
            FILE_DEVICE_SCREEN = 0x0000001c,
            FILE_DEVICE_SOUND = 0x0000001d,
            FILE_DEVICE_STREAMS = 0x0000001e,
            FILE_DEVICE_TAPE = 0x0000001f,
            FILE_DEVICE_TAPE_FILE_SYSTEM = 0x00000020,
            FILE_DEVICE_TRANSPORT = 0x00000021,
            FILE_DEVICE_UNKNOWN = 0x00000022,
            FILE_DEVICE_VIDEO = 0x00000023,
            FILE_DEVICE_VIRTUAL_DISK = 0x00000024,
            FILE_DEVICE_WAVE_IN = 0x00000025,
            FILE_DEVICE_WAVE_OUT = 0x00000026,
            FILE_DEVICE_8042_PORT = 0x00000027,
            FILE_DEVICE_NETWORK_REDIRECTOR = 0x00000028,
            FILE_DEVICE_BATTERY = 0x00000029,
            FILE_DEVICE_BUS_EXTENDER = 0x0000002a,
            FILE_DEVICE_MODEM = 0x0000002b,
            FILE_DEVICE_VDM = 0x0000002c,
            FILE_DEVICE_MASS_STORAGE = 0x0000002d,
            FILE_DEVICE_SMB = 0x0000002e,
            FILE_DEVICE_KS = 0x0000002f,
            FILE_DEVICE_CHANGER = 0x00000030,
            FILE_DEVICE_SMARTCARD = 0x00000031,
            FILE_DEVICE_ACPI = 0x00000032,
            FILE_DEVICE_DVD = 0x00000033,
            FILE_DEVICE_FULLSCREEN_VIDEO = 0x00000034,
            FILE_DEVICE_DFS_FILE_SYSTEM = 0x00000035,
            FILE_DEVICE_DFS_VOLUME = 0x00000036,
            FILE_DEVICE_SERENUM = 0x00000037,
            FILE_DEVICE_TERMSRV = 0x00000038,
            FILE_DEVICE_KSEC = 0x00000039,
            FILE_DEVICE_FIPS = 0x0000003A,
            FILE_DEVICE_INFINIBAND = 0x0000003B,
            FILE_DEVICE_VMBUS = 0x0000003E,
            FILE_DEVICE_CRYPT_PROVIDER = 0x0000003F,
            FILE_DEVICE_WPD = 0x00000040,
            FILE_DEVICE_BLUETOOTH = 0x00000041,
            FILE_DEVICE_MT_COMPOSITE = 0x00000042,
            FILE_DEVICE_MT_TRANSPORT = 0x00000043,
            FILE_DEVICE_BIOMETRIC = 0x00000044,
            FILE_DEVICE_PMI = 0x00000045,
            FILE_DEVICE_EHSTOR = 0x00000046,
            FILE_DEVICE_DEVAPI = 0x00000047,
            FILE_DEVICE_GPIO = 0x00000048,
            FILE_DEVICE_USBEX = 0x00000049,
            FILE_DEVICE_CONSOLE = 0x00000050,
            FILE_DEVICE_NFP = 0x00000051,
            FILE_DEVICE_SYSENV = 0x00000052,
            FILE_DEVICE_VIRTUAL_BLOCK = 0x00000053,
            FILE_DEVICE_POINT_OF_SERVICE = 0x00000054,
            FILE_DEVICE_STORAGE_REPLICATION = 0x00000055,
            FILE_DEVICE_TRUST_ENV = 0x00000056,
            FILE_DEVICE_UCM = 0x00000057,
            FILE_DEVICE_UCMTCPCI = 0x00000058,
            FILE_DEVICE_PERSISTENT_MEMORY = 0x00000059,
            FILE_DEVICE_NVDIMM = 0x0000005a,
            FILE_DEVICE_HOLOGRAPHIC = 0x0000005b,
            FILE_DEVICE_SDFXHCI = 0x0000005c,
            FILE_DEVICE_UCMUCSI = 0x0000005d
        }

        [Flags]
        public enum Method : uint
        {
            METHOD_BUFFERED = 0,
            METHOD_IN_DIRECT = 1,
            METHOD_OUT_DIRECT = 2,
            METHOD_NEITHER = 3
        }

        [Flags]
        public enum Access : uint
        {
            FILE_READ_DATA = (0x0001),            // file & pipe
            FILE_LIST_DIRECTORY = (0x0001),       // directory
            FILE_WRITE_DATA = (0x0002),           // file & pipe
            FILE_ADD_FILE = (0x0002),             // directory
            FILE_APPEND_DATA = (0x0004),          // file
            FILE_ADD_SUBDIRECTORY = (0x0004),     // directory
            FILE_CREATE_PIPE_INSTANCE = (0x0004), // named pipe
            FILE_READ_EA = (0x0008),                // file & directory
            FILE_WRITE_EA = (0x0010),               // file & directory
            FILE_EXECUTE = (0x0020),                // file
            FILE_TRAVERSE = (0x0020),               // directory
            FILE_DELETE_CHILD = (0x0040),           // directory
            FILE_READ_ATTRIBUTES = (0x0080),        // all
            FILE_WRITE_ATTRIBUTES = (0x0100),       // all
            /*
            FILE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF),
            FILE_GENERIC_READ = (STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE),
            FILE_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE),
            FILE_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE)
            */
        }

        private static uint CTL_CODE(DeviceType deviceType, uint function, Method method, Access access)
        {
            return (((uint)deviceType) << 16) | (((uint)access) << 14) | ((function) << 2) | ((uint)method);
        }

        private SafeFileHandle hDevice;

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public TokenDriver()
        {

        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public bool LoadDriverNt(string lpBinaryPathName)
        {
            try
            {
                using (RegistryKey servicesKey = Registry.LocalMachine.OpenSubKey(@"\SYSTEM\CurrentControlSet\Services\", true))
                {
                    servicesKey.CreateSubKey("NtTokenDriver");
                    using (RegistryKey driverKey = servicesKey.OpenSubKey("NtTokenDriver", true))
                    {
                        driverKey.SetValue("ImagePath", lpBinaryPathName);
                        driverKey.SetValue("Start", 0x03);
                        driverKey.SetValue("Type", 0x01);
                        driverKey.SetValue("ErrorControl", 0x01);
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is ArgumentNullException)
                {

                }

                if (ex is ObjectDisposedException)
                {

                }

                if (ex is System.Security.SecurityException)
                {

                }

                Console.WriteLine(ex.Message);
                return false;
            }

            uint status = NtLoadDriver(@"\SYSTEM\CurrentControlSet\Services\NtTokenDriver");
            if (0 != status)
            {
                Misc.GetNtError("NtLoadDriver", status);
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public bool LoadDriverSC(string lpBinaryPathName)
        {
            IntPtr hSCManager = advapi32.OpenSCManager(
                string.Empty,
                string.Empty, 
                Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CREATE_SERVICE
            );
            if (IntPtr.Zero == hSCManager)
            {
                Misc.GetWin32Error("OpenSCManager");
                return false;
            }

            IntPtr hService = advapi32.CreateService(
                hSCManager,
                "ScTokenDriver", "ScTokenDriver",
                Winsvc.dwDesiredAccess.SERVICE_START,
                Winsvc.dwServiceType.SERVICE_KERNEL_DRIVER,
                Winsvc.dwStartType.SERVICE_DEMAND_START,
                Winsvc.dwErrorControl.SERVICE_ERROR_NORMAL,
                lpBinaryPathName,
                string.Empty, string.Empty, string.Empty, string.Empty, string.Empty
            );
            if (IntPtr.Zero == hService)
            {
                Misc.GetWin32Error("CreateService");
                return false;
            }

            if (!advapi32.StartService(hService, 0, new string[0]))
            {
                Misc.GetWin32Error("StartService");
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public bool Connect()
        {
            hDevice = CreateFile(
                "\\\\.\\TokenLink",
                Winnt.ACCESS_MASK.GENERIC_ALL,
                SHARE_MODE.FILE_SHARE_LOCKED,
                IntPtr.Zero,
                CREATION_DISPOSITION.OPEN_EXISTING,
                FILE_ATTRIBUTES.FILE_ATTRIBUTE_SYSTEM,
                IntPtr.Zero
            );

            if (hDevice.IsInvalid)
            {
                Misc.GetWin32Error("CreateFile");
                return false;
            }

            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void _SendIOCTL(byte[] inBuffer, uint Function)
        {
            int nInBuffer = Buffer.ByteLength(inBuffer);
            IntPtr lpInBuffer = Marshal.AllocHGlobal(nInBuffer);

            uint ControlCode = CTL_CODE(DeviceType.FILE_DEVICE_UNKNOWN, Function, Method.METHOD_BUFFERED, Access.FILE_WRITE_DATA);
            Console.WriteLine("[*] Sending IOCTL {0}", ControlCode);
            try
            {
                Marshal.Copy(inBuffer, 0, lpInBuffer, nInBuffer);
                uint lpBytesReturned = 0;
                if(!DeviceIoControl(hDevice, ControlCode, lpInBuffer, (uint)nInBuffer, IntPtr.Zero, 0, ref lpBytesReturned, IntPtr.Zero))
                {
                    Misc.GetWin32Error("DeviceIoControl");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            { 
                Marshal.FreeHGlobal(lpInBuffer);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private byte[] _RecieveIOCTL(uint nOutBuffer)
        {
            byte[] returnedData;
            IntPtr lpOutBuffer = Marshal.AllocHGlobal((int)nOutBuffer);
            uint ControlCode = CTL_CODE(DeviceType.FILE_DEVICE_UNKNOWN, 0x802, Method.METHOD_BUFFERED, Access.FILE_READ_DATA);

            try
            {
                uint lpBytesReturned = 0;
                if (!DeviceIoControl(hDevice, ControlCode, IntPtr.Zero, 0, lpOutBuffer, nOutBuffer, ref lpBytesReturned, IntPtr.Zero))
                {
                    Misc.GetWin32Error("DeviceIoControl");
                    return null;
                }
                returnedData = new byte[lpBytesReturned];
                Marshal.Copy(lpOutBuffer, returnedData, 0, (int)lpBytesReturned);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(lpOutBuffer);
            }

            return returnedData;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private byte[] _SendRecieveIOCTL(byte[] inBuffer, uint Function)
        {
            byte[] returnedData;

            int nInBuffer = Buffer.ByteLength(inBuffer);
            IntPtr lpInBuffer = Marshal.AllocHGlobal(nInBuffer);

            int nOutBuffer = 2048;
            IntPtr lpOutBuffer = Marshal.AllocHGlobal(nOutBuffer);

            uint ControlCode = CTL_CODE(DeviceType.FILE_DEVICE_UNKNOWN, Function, Method.METHOD_BUFFERED, Access.FILE_WRITE_DATA | Access.FILE_READ_DATA);
            Console.WriteLine("[*] Sending IOCTL {0}", ControlCode);
            try
            {
                Marshal.Copy(inBuffer, 0, lpInBuffer, nInBuffer);
                uint lpBytesReturned = 0;
                if (!DeviceIoControl(hDevice, ControlCode, lpInBuffer, (uint)nInBuffer, lpOutBuffer, (uint)nOutBuffer, ref lpBytesReturned, IntPtr.Zero))
                {
                    Misc.GetWin32Error("DeviceIoControl");
                    return new byte[0];
                }
                returnedData = new byte[lpBytesReturned];
                Marshal.Copy(lpOutBuffer, returnedData, 0, (int)lpBytesReturned);
                Console.WriteLine("[+] {0} Bytes Returned", lpBytesReturned);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return new byte[0];
            }
            finally
            {
                Marshal.FreeHGlobal(lpInBuffer);
                Marshal.FreeHGlobal(lpOutBuffer);
            }

            return returnedData;
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void AddTokenPrivilege(PRIVILEGES privilege)
        {
            byte[] result = _SendRecieveIOCTL(BitConverter.GetBytes((ulong)privilege), 0x805);

            _AddTokenPrivilege(result);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void AddTokenPrivilege(PRIVILEGE_DATA data)
        {
            int structSize = Marshal.SizeOf(data);
            IntPtr ptrData = Marshal.AllocHGlobal(structSize);
            Marshal.StructureToPtr(data, ptrData, true);

            byte[] arrData = new byte[structSize];
            Marshal.Copy(ptrData, arrData, 0, structSize);

            Marshal.FreeHGlobal(ptrData);
            byte[] result =  _SendRecieveIOCTL(arrData, 0x806);

            _AddTokenPrivilege(result);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private void _AddTokenPrivilege(Byte[] result)
        {
            const int RETURN_SIZE = sizeof(ulong) * 9;

            IntPtr buffer1 = Marshal.AllocHGlobal(RETURN_SIZE);
            Marshal.Copy(result, 0, buffer1, RETURN_SIZE);

            long[] buffer2 = new long[9];
            Marshal.Copy(buffer1, buffer2, 0, 9);

            ulong[] addresses = buffer2.Select(x => (ulong)x).ToArray();
            Console.WriteLine("[+] PEPROCESS Base Address : 0x{0}", addresses[0].ToString("X4"));
            Console.WriteLine();
            Console.WriteLine("[+] EX_FAST_REF Base Address : 0x{0}", addresses[1].ToString("X4"));
            Console.WriteLine("[+] EX_FAST_REF Data         : 0x{0}", addresses[2].ToString("X4"));
            Console.WriteLine();
            Console.WriteLine("[+] TOKEN Base Address                 : 0x{0}", addresses[3].ToString("X4"));
            Console.WriteLine("[+] PSEP_TOKEN_PRIVILEGES Base Address : 0x{0}", addresses[4].ToString("X4"));
            Console.WriteLine();
            Console.WriteLine("[+] Current Present Value : 0x{0}", addresses[5].ToString("X4"));
            Console.WriteLine("[+] Updated Present Value : 0x{0}", addresses[6].ToString("X4"));
            Console.WriteLine("[+] Enabled               : 0x{0}", addresses[7].ToString("X4"));
            Console.WriteLine("[+] EnabledByDefault      : 0x{0}", addresses[8].ToString("X4"));
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void SendMessage()
        {
            _SendIOCTL(Encoding.Unicode.GetBytes("UnFreeze Token\0"), 0x801);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void UnFreezeToken()
        {
            byte[] result = _SendRecieveIOCTL(new byte[0], 0x803);
            _UnFreezeToken(result);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void UnFreezeToken(uint pid)
        {
            byte[] result = _SendRecieveIOCTL(BitConverter.GetBytes(pid), 0x804);
            _UnFreezeToken(result);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        private void _UnFreezeToken(Byte[] result)
        {
            const int RETURN_SIZE = sizeof(ulong) * 5;

            IntPtr buffer1 = Marshal.AllocHGlobal(RETURN_SIZE);
            Marshal.Copy(result, 0, buffer1, RETURN_SIZE);

            long[] buffer2 = new long[5];
            Marshal.Copy(buffer1, buffer2, 0, 5);

            ulong[] addresses = buffer2.Select(x => (ulong)x).ToArray();
            Console.WriteLine("[+] PEPROCESS Base Address  : 0x{0}", addresses[0].ToString("X4"));
            Console.WriteLine("[+] PEPROCESS Flags2 Offset : 0x{0}", addresses[1].ToString("X4"));
            Console.WriteLine();
            Console.WriteLine("[+] Flags2 Original Value : 0x{0}", addresses[2].ToString("X4"));
            Console.WriteLine("[+] Flags2 Updated Value  : 0x{0}", addresses[3].ToString("X4"));
            Console.WriteLine("[+] Flags2 band           : 0x{0}", addresses[4].ToString("X4"));
            if (0x8000 == addresses[4])
                Console.WriteLine("[*] Token UnFrozen");
            else if (0x0 == addresses[4])
                Console.WriteLine("[*] Token ReFrozen");
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void RecieveMessage()
        {
            Console.WriteLine(Encoding.Unicode.GetString(_RecieveIOCTL(1024)));
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            if (!hDevice.IsInvalid)
                hDevice.Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        ~TokenDriver()
        {
            Dispose();
        }
    }
}
