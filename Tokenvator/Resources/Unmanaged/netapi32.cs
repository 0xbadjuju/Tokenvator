using System;
using System.Runtime.InteropServices;

namespace Tokenvator
{
	class netapi32
	{
		public enum NetJoinStatus
		{
			NetSetupUnknownStatus = 0,
			NetSetupUnjoined,
			NetSetupWorkgroupName,
			NetSetupDomainName
		}
	
		[DllImport("Netapi32.dll", SetLastError=true)]
		public static extern Int32 NetGetJoinInformation(
			String server,
			out IntPtr domain,
			out NetJoinStatus status);
	}
}