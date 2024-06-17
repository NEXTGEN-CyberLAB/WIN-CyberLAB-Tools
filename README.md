# NEXTGEN CyberLAB Windows Easy Script :)
Hi there :)

This is the CyberLAB handy tools script - please note it is in Alpha at the moment :) If you've found this, congrats! You're either part of NEXTGEN, or you're a close part of the NEXTGEN Circle of trust!

Please download the script and run it locally for best results (or copy and paste the raw code in to PowerShell ISE.

Technically you can pipe this script in to powershell directly using something like this, but it's not really built for this yet:

```powershell
iex (iwr "https://raw.githubusercontent.com/NEXTGEN-CyberLAB/WIN-CyberLAB-Tools/main/CyberLAB-Script.ps1").Content
```
Just note that if you're doing that on a brand new server, you might need to have run Internet Explorer (yes, that internet explorer) first for iwr to work. 

Run this before you use the script at all:

```powershell
Set-ExecutionPolicy Unrestricted
```

Otherwise the script will not run. Obviously once you're done, set the execution policy to whatever matches your needs

Any questions, contact hayden.loader@nextgen.group

Cheers,
Hayden.
