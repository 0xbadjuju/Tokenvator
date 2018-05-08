# Tokenvator
A tool to elevate privilege with Windows Tokens

This tool has two methods of operation - interactive and argument modes

Interactive Mode: <br/>
C:\> tokenvator.exe <br/>
(Tokens) > steal_token 908 cmd.exe <br/>
(Tokens) > <br/>

Arguments Mode: <br/>
C:\> tokenvator.exe steal_token 908 cmd.exe <br/>
C:\> <br/>

### Methods

* #### GetSystem
  * **Optional Parameters:** Process ID, Command
  * **Examples:** <br/>
  (Tokens) > GetSystem <br/>
  or <br />
  (Tokens) > GetSystem 504 <br/>
  or <br />
  (Tokens) > GetSystem 504 regedit.exe <br/>
  
* #### GetTrustedInstaller
  * **Optional Parameters:** Command
  * **Examples:** <br/>
  (Tokens) > GetTrustedInstaller <br/>
  or <br />
  (Tokens) > GetTrustedInstaller regedit.exe <br/>
  
* #### Steal_Token
  * **Parameters:** Process ID
  * **Optional Parameters:** Command
  * **Examples:** <br/>
  (Tokens) > StealToken 1008 <br/>
  or <br />
  (Tokens) > StealToken calc regedit.exe <br/>
  or <br />
  (Tokens) > StealToken 1008 regedit.exe <br/>
  
* #### BypassUAC
  * **Parameters:** Process ID
  * **Optional Parameters:** Command
  * **Examples:** <br/>
  (Tokens) > BypassUAC 1008 <br/>
  or <br />
  (Tokens) > BypassUAC regedit.exe <br/>
  or <br />
  (Tokens) > BypassUAC 1008 regedit.exe <br/>
  
* #### List_Privileges
  * **Parameters:** -
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > List_Privileges <br/>
  
* #### Set_Privileges
  * **Parameters:** Privilege
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > Set_Privileges SeSecurityPrivilege<br/> 
  
* #### List_Processes
  * **Parameters:** -
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > List_Processes<br/> 
  
* #### List_Processes_WMI
  * **Parameters:** -
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > List_Processes_WMI<br/> 
  
* #### Find_User_Processes
  * **Parameters:** Username
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > Find_User_Processes domain\user<br/> 
  
* #### Find_User_Processes_WMI
  * **Parameters:** Username
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > Find_User_Processes_WMI domain\user<br/> 

* #### List_User_Sessions
  * **Parameters:** -
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > List_User_Sessions<br/> 
  
* #### WhoAmI
  * **Parameters:** -
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > WhoAmI<br/> 

* #### RevertToSelf
  * **Parameters:** -
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > RevertToSelf<br/> 
  
* #### Run
  * **Parameters:** Command
  * **Optional Parameters:** -
  * **Examples:** <br/>
  (Tokens) > Run cmd.exe<br/> 
  
* #### Compiling <br/>
* git clone https://github.com/0xbadjuju/Tokenvator.git <br/>
* Import the project into Visual Studio. The current target framework is .Net 3.5. <br/>
* Create a key for Strong Name signing: <br/>
  * cd Tokenvator\Tokenvator\ <br/>
  * C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin\x64\sn.exe -k sgKey.snk <br/>
* Build Solution <br>



### Author, Contributors, and License

Author: Alexander Leary (@0xbadjuju), NetSPI - 2018

License: BSD 3-Clause

Required Dependencies: None
