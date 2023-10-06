# Tokenvator
A tool to alter privilege with Windows Tokens

For documentation please see the wiki:<br> 
https://github.com/0xbadjuju/Tokenvator/wiki

Building instructions can be found here:<br>
https://github.com/0xbadjuju/Tokenvator/wiki/Building-Tokenvator

This project now utilizes [MonkeyWorks](https://github.com/NetSPI/MonkeyWorks), to clone issue the following command:<br>
**git clone _--recursive_ https://github.com/0xbadjuju/Tokenvator.git**

`Tokenvator.exe GetSystem /Process:3016 /command:'cmd.exe /c net user /add testuser Password1'`

### Author, Contributors, and License

Author: Alexander Polce Leary (@0xbadjuju), NetSPI - 2018

License: BSD 3-Clause

Dependencies: 
[MonkeyWorks](https://github.com/0xbadjuju/MonkeyWorks)
[DInvoke](https://github.com/TheWover/DInvoke)
