# Get-bADpasswords
[![License](https://img.shields.io/badge/License-BSD%203--Clause-orange.svg)](https://opensource.org/licenses/BSD-3-Clause) ![PowerShell 3 | 4 | 5](https://img.shields.io/badge/PowerShell-3%20|%204%20|%205-0000FF.svg) ![Windows Server 2008 R2 | 2012 R2 | 2016](https://img.shields.io/badge/Windows%20Server-2008%20R2%20|%202012%20R2%20|%202016-007bb8.svg) ![.NET Framework 4.5.1+](https://img.shields.io/badge/.NET%20Framework-4.5.1%2B-007FFF.svg) ![Visual Studio 2017](https://img.shields.io/badge/Visual%20Studio-2017-383278.svg)

Get insights into the actual strength and quality of passwords in Active Directory.

## Dependencies

### Microsoft Visual C++ Redistributable Package
Microsoft Visual C++ Redistributable Package is required by our PSI DLL. This DLL is reponsible for parsing the leaked-password binary file and performing comparisons against it. The source code for the DLL can be found [here](./Source).

##### Installation step-by-step
* Go to [Microsoft Latest Supported Visual C++ Download](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads)
* Download and install the Visual Studio 2017 version of the Visual C++ Redistributable Package for your target platform
  * For 32-bit systems: vc_redist.x86.exe
  * For 64-bit systems: vc_redist.x64.exe
* No restart required

#### Microsoft .NET Framework 4.5.1+
Microsoft .NET Framework 4.5.1+ is required by the DSInternals 3.0 PowerShell module by Michael Grafnetter.

##### Installation step-by-step
* Go to [Microsoft .NET Framework 4.5 Download](https://www.microsoft.com/en-us/download/details.aspx?id=30653)
* Download and install the .NET Framework 4.5 in your preferred language
* (Restart? No restart?) required

## Prerequisites

#### DSInternals 3.0 PowerShell Module
This module is used to query the Active Directory and fetch user information (SAM Account Name, E-mail, Password Hash, etc.). The source code for this module can be found [here](https://github.com/MichaelGrafnetter/DSInternals).

##### Installation step-by-step
* Go to [DSInternals 3.0 PowerShell Module Download](https://www.powershellgallery.com/packages/DSInternals/3.0)
* Download and install the DSInternals 3.0 PowerShell Module
* No restart required

Alternatively, you can install DSInternals 3.0 through PowerShellGet by running the following PowerShell command:
```powershell
Install-Module -Name DSInternals
```

### Leaked password list
This file contains a binary packed list of leaked password hashes from the Troy Hunt PwnedPasswords list. The file is too big (8 GB) for GitHub (max 25 MB), so we host it on our SharePoint instead. 

##### Installation step-by-step
* Go to [Improsec Leaked Password List](https://improsec-my.sharepoint.com/:u:/p/jhh/EdyYIoFELcZBle_0OQX6D1MB51mgZLZQqNx1ELrBs3D_DQ?e=waNigh)
  * SHA1: 334E236FEA9DB781BE646BB2F80394D9C039BE02
* Download the _leaked-passwords.bin_ file
* Place the file in the same folder as the rest of this project

## Installing

A step by step series of examples that tell you how to get a development env running

Say what the step will be

```
Give the example
```

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Deployment

Add additional notes about how to deploy this on a live system

## Authors

* [**Jakob H. Heidelberg**](https://github.com/ZilentJack) - *Initial work* - 
* [**Valdemar Carøe**](https://github.com/VirtualPuppet) - *Initial work* - 
* [**Nichlas Falk**](https://github.com/...) - *Initial work* - 

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [Michael Grafnetter](https://github.com/MichaelGrafnetter) for the amazing [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) framework
* [Troy Hunt](https://github.com/troyhunt) for the amazing [PwnedPasswords list](https://haveibeenpwned.com/Passwords)
