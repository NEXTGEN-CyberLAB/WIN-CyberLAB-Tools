# NEXTGEN CyberLAB Windows Easy Script :)
Hi there :)

This is the CyberLAB handy tools script - please note it is in Beta at the moment :) 

Please download the script and run it locally for best results (or copy and paste the raw code in to PowerShell ISE. Must be run as an Admin user.

Technically you can pipe this script in to powershell directly using something like this, but it's not really built for this yet:

```powershell
iex (iwr "https://raw.githubusercontent.com/NEXTGEN-CyberLAB/WIN-CyberLAB-Tools/main/CyberLAB-quickstart.ps1" -UseBasicParsing).Content
```

Run this before you use the script at all:

```powershell
Set-ExecutionPolicy Unrestricted
```

Otherwise the script will not run. Obviously once you're done, set the execution policy to whatever matches your needs

Any questions, contact hayden.loader@nextgen.group

Cheers,
Hayden.
