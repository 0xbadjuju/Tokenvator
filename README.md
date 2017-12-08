# Tokenvator
A tool to elevate privilege with Windows Tokens

### Methods

* #### GetSystem
  * **Optional Parameters:** Process ID, Command
  * **Example:** <br/>
  (Tokens) > GetSystem <br/>
  (Tokens) > GetSystem 504 <br/>
  (Tokens) > GetSystem 504 regedit.exe <br/>
  
* #### GetTrustedInstaller
  * **Optional Parameters:** Command
  * **Example:** <br/>
  (Tokens) > GetTrustedInstaller <br/>
  (Tokens) > GetTrustedInstaller regedit.exe <br/>
  
* #### StealToken
  * **Parameters:** Process ID
  * **Optional Parameters:** Command
  * **Example:** <br/>
  (Tokens) > StealToken 1008 <br/>
  (Tokens) > StealToken 1008 regedit.exe <br/>
  
* #### BypassUAC
  * **Parameters:** Process ID
  * **Optional Parameters:** Command
  * **Example:** <br/>
  (Tokens) > BypassUAC 1008 <br/>
  (Tokens) > BypassUAC 1008 regedit.exe <br/>

### Author, Contributors, and License

Author: Alexander Leary (@0xbadjuju), NetSPI - 2017

License: BSD 3-Clause

Required Dependencies: None
