# Tokenvator
A tool to elevate privilege with Windows Tokens

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
  
* #### StealToken
  * **Parameters:** Process ID
  * **Optional Parameters:** Command
  * **Examples:** <br/>
  (Tokens) > StealToken 1008 <br/>
  or <br />
  (Tokens) > StealToken 1008 regedit.exe <br/>
  
* #### BypassUAC
  * **Parameters:** Process ID
  * **Optional Parameters:** Command
  * **Examples:** <br/>
  (Tokens) > BypassUAC 1008 <br/>
  or <br />
  (Tokens) > BypassUAC 1008 regedit.exe <br/>

### Author, Contributors, and License

Author: Alexander Leary (@0xbadjuju), NetSPI - 2017

License: BSD 3-Clause

Required Dependencies: None
