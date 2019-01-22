<#
  .SYNOPSIS
    Compare password hashes of enabled Active Directory users with one or more lists of bad, weak or non-compliant passwords (e.g. hackers first guess during a brute-force attack).
    - Multiple word lists can be used.
    - Can write log and CSV file output.
    - Must be excuted with 'Domain Admin' or 'Domain Controller' permissions (or equivalent).
    - Version 2.0 also checks for leaked passwords (see Troy Hunt: https://www.troyhunt.com/pwned-passwords-now-as-ntlm-hashes/).
    
    Requires PS Module "DSInternals" to be present on executing host. Please follow install instructions from there.
    - Found here: https://www.powershellgallery.com/packages/DSInternals/
    - More info:  https://www.dsinternals.com/en/
    - .NET Framework 4.5.1 is required for the module to be fully functional. Unfortunately, PowerShell versions prior to 5 ignore this prerequisite.

    Required for Psi.dll:
    - Microsoft Visual C++ Redistributable for Visual Studio 2017 x86/x64 (depending on version).

    Note: this script does not modify or permutate input from word lists, like switching to upper/lower case etc. Each word in word list is taken as-is. Use other tools to generate word lists if needed.
	
    License: BSD 3-Clause

  .DESCRIPTION
    Compare password hashes of active Active Directory users with list of bad, weak or non-compliant passwords.

  .LINK
    Get latest version here: https://github.com/Improsec/Get-bADpasswords

    Old project: https://github.com/ZilentJack/Get-bADpasswords

  .NOTES
    Authored by    : Improsec ApS / @Improsec
    Date created   : 01/10-2015
    Last modified  : 12/12-2018
  
    Find us here:
    - https://www.improsec.com
    - https://github.com/improsec
    - https://twitter.com/improsec
    - https://www.facebook.com/improsec

    The very cool DSInternals module is authored by Michael Grafnetter - HUGE THANX to Michael for his great work and help! 

    Version history:
    - 1.00 Basic functionality
    - 2.00 Code optimization and added search for leaked password hashes (released on GitHub)
    
    Tested on:
     - WS 2012 R2, WS 2016, WS 2019
#>

# ================ #
# CONFIGURATION => #
# ================ #

# Domain user variables
$strDomain = "IMPROSEC"
$naming_context = 'DC=AD,DC=IMPROSEC,DC=COM'

# Files
$weak_password_files = @('.\Accessible\Wordlists\BadPasswords.txt', '.\Accessible\Wordlists\BadCustom.txt')
$leak_password_files = @('.\leaked-passwords.bin')

# Logging
$current_timestamp = Get-Date -Format ddMMyyyy-HHmmss

$log_filename  = ".\Accessible\Logs\log_$strDomain-$current_timestamp.txt"
$csv_filename  = ".\Accessible\CSVs\UsersWithBadPasswords_$strDomain-$current_timestamp.csv"

$write_to_log_file = $true
$write_to_csv_file = $true

$log_weak_passwords = $false # Will log plain-text password for users with weak passwords

# Result dispatch
$mail_smtp = "mail-smtp.yourcompany.com"
$mail_recipient = "Get-bADpassword <badpwd@yourcompany.com>"
$mail_sender = "Get-bADpasswords <badpwd@yourcompany.com>"
$mail_subject = "Get-bADpasswords $($strDomain.ToUpper()) $current_timestamp"

# ================ #
# PREPROCESSING => #
# ================ #

$current_directory = Split-Path $MyInvocation.MyCommand.Path
[System.IO.Directory]::SetCurrentDirectory($current_directory);

[System.IO.Directory]::CreateDirectory('.\Accessible\Logs')
[System.IO.Directory]::CreateDirectory('.\Accessible\CSVs')

$psi_library_name = ''

if ([System.Environment]::Is64BitOperatingSystem -and [System.Environment]::Is64BitProcess)
{
	$psi_library_name = '.\\PSI\\Psi_x64.dll'
}
else
{
	$psi_library_name = '.\\PSI\\Psi_x86.dll'
}

# Include a few helper files
. '.\Helper_Logging'
. '.\Helper_PasswordsLeak'
. '.\Helper_PasswordsWeak'

# ================ #
# VARIABLES =====> #
# ================ #

# constant(s)
$empty_nt_hash = '31d6cfe0d16ae931b73c59d7e0c089c0'
                  

# miscellaneous
$script_version = '2.00'

# ================ #
# FUNCTIONS =====> #
# ================ #

Function Get-AliveDC
{
    Param
    (
    [Parameter(Mandatory=$true,
                   Position=0)]
    $strDomainName
    )
    $domainContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $strDomainName);
    $DCsInDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext).FindAllDomainControllers();

    If (!($DCsInDomain))
    {
        Break
    }

    Foreach ($DC in $DCsInDomain)
    {
        If(Test-Connection $DC.Name -Count 1)
        {
            Return $DC.Name
        }
    }
}

Function Find-ArrayItem
{
	Param
	(
        [Parameter(Mandatory=$true)]
		[string[]]
		$array,
	
        [Parameter(Mandatory=$true)]
		[string]
		$item
	)
	
	if ($array -ne $null)
	{
		foreach ($object in $array)
		{
			if ($object -eq $item)
			{
				return $true
			}
		}
	}
	
	return $false
}

# ================ #
# SCRIPT ========> #
# ================ #

# Domain
$domain_controller_fqdn = Get-AliveDC -strDomainName $strDomain

if (!($domain_controller_fqdn))
{
    Log-Automatic -string "A live DC in $strDomain was not found. Exiting.`n" -type 'info' -timestamp
    exit
}

$domain_controller = $domain_controller_fqdn.Split('.')[0]

Log-Automatic -string "Version:`t'$script_version'." -type 'info' -timestamp
Log-Automatic -string "Log file:`t'$log_filename'." -type 'info' -timestamp
Log-Automatic -string "CSV file:`t'$csv_filename'.`n" -type 'info' -timestamp

# Populate array with usernames and NT hash values for enabled users only
Log-Automatic -string "Calling Get-ADReplAccount with parameters (DC = '$domain_controller', NC = '$naming_context')..." -type 'info' -timestamp

$users = $null

try
{
    $users = Get-ADReplAccount -All -Server $domain_controller -NamingContext $naming_context | Where {$_.Enabled -eq $true -and $_.SamAccountType -eq 'User'} | Select SamAccountName,@{Name="NTHashHex";Expression={ConvertTo-Hex $_.NTHash}}
}
catch
{
	Log-Automatic -string $_.Exception.Message -type 'fail' -timestamp
	exit
}

if ($users -ne $null -and $users.count -ge 1)
{
	Log-Automatic -string "The AD returned $($users.count) users.`n" -type 'info' -timestamp
 
	$passwords_empty = 0
	$passwords_weak = 0
	$passwords_leak = 0
	
	# Isolate the user hashes for comparison with weak and leaked passwords
	$user_hashes = @()
    $usernames_with_empty_passwords = @()
	
	foreach ($user in $users)
	{
		if ($user.NTHashHex -eq $empty_nt_hash)
		{
            $usernames_with_empty_passwords += $user.SamAccountName;
		}
		else
		{
			$user_hashes += $user.NTHashHex; 
		}
	}
	
	# Test for weak passwords
	$weak_passwords = @{}

	if (Generate-WeakPasswords -sources $weak_password_files -results ([ref]$weak_passwords))
	{
		Log-Automatic -string "Successfully loaded weak password source files.`n" -type 'info' -timestamp
		Test-WeakPasswords -user_hashes $user_hashes -weak_hashes ([ref]$weak_passwords)
	}
	else
	{
		Log-Automatic -string "No weak passwords loaded from weak password lists.`n" -type 'fail' -timestamp
	}

	# Test for leak passwords
	$leak_passwords = @()
	
	Test-LeakPasswords -sources $leak_password_files -user_hashes $user_hashes -results ([ref]$leak_passwords)
	
	# Compare results with user accounts
	$users_with_weak_passwords = ''
	$users_with_leak_passwords = ''
	$users_with_empty_passwords = ''
	
    foreach ($username in $usernames_with_empty_passwords)
    {
		$passwords_empty++
		$users_with_empty_passwords += "$username; "

		Log-Automatic -string "Empty password found for user: '$username'." -type 'info' -timestamp

		if ($write_to_csv_file)
		{
			Log-Specific -filename $csv_filename -string "empty;$($username)"
		}
    }

	foreach ($user in $users)
	{
		if ($weak_passwords.ContainsKey($user.NTHashHex))
		{
			$passwords_weak++;
			$users_with_weak_passwords += "$($user.SamAccountName); "
			
			if ($log_weak_passwords)
			{
				Log-Automatic -string "Weak password found for user: '$($user.SamAccountName)' = '$($weak_passwords[$user.NTHashHex])'" -type 'info' -timestamp
			}
			else
			{
				Log-Automatic -string "Weak password found for user: '$($user.SamAccountName)'" -type 'info' -timestamp
			}
			
			if ($write_to_csv_file)
			{
				Log-Specific -filename $csv_filename -string "weak;$($user.SamAccountName);$($user.NTHashHex)"
			}
		}
		elseif (Find-ArrayItem -array $leak_passwords -item $user.NTHashHex)
		{
			$passwords_leak++;
			$users_with_leak_passwords += "$($user.SamAccountName); "
			
			Log-Automatic -string "Leak password found for user: '$($user.SamAccountName)'" -type 'info' -timestamp
				
			if ($write_to_csv_file)
			{
				Log-Specific -filename $csv_filename -string "leak;$($user.SamAccountName);$($user.NTHashHex)"
			}
		}
	}
	
	Log-Automatic -string " "
	Log-Automatic -string "Found a total of '$passwords_empty' user(s) with empty passwords" -type 'info' -timestamp
	Log-Automatic -string "Found a total of '$passwords_weak' user(s) with weak passwords" -type 'info' -timestamp
	Log-Automatic -string "Found a total of '$passwords_leak' user(s) with leak passwords" -type 'info' -timestamp
	
	# Test for shared passwords
	$shared_passwords = $users | Select-Object SamAccountName,NTHashHex | Group-Object -Property NTHashHex | Where-Object {$_.Count -gt 1}
	$shared_info = $shared_passwords | Measure-Object -Property 'count' -Sum

	$shared_passwords_sorted = $shared_passwords | Sort-Object -Descending -Property Count | Select-Object Count,Name,@{Name="Usernames";Expression={$_.Group.SamAccountName}}
	$shared_passwords_present = @()

	foreach ($password in $shared_passwords_sorted)
	{
		$shared_passwords_present += $($password.Usernames -join '; ')
	}

	# Send summary e-mail
	$mail_body = "Total users: '$($users.count)'`n"
    $mail_body += "Empty passwords found: '$passwords_empty' ($([Math]::round((($passwords_empty / $users.count) * 100)))%)`n"
	$mail_body += "Weak passwords found: '$passwords_weak' ($([Math]::round((($passwords_weak / $users.count) * 100)))%)`n"
	$mail_body += "Leak passwords found: '$passwords_leak' ($([Math]::round((($passwords_leak / $users.count) * 100)))%)`n"
	$mail_body += "Number of passwords shared: '$($shared_info.count)' ($([Math]::round((($($shared_info.count) / $users.count) * 100)))%)`n"
	$mail_body += "Number of users sharing passwords: '$($shared_info.sum)' ($([Math]::round((($($shared_info.sum) / $users.count) * 100)))%)`n`n"
	
	$mail_body += "Users with empty passwords:`n"
	$mail_body += "$users_with_empty_passwords`n`n"

	$mail_body += "Users with weak passwords:`n"
	$mail_body += "$users_with_weak_passwords`n`n"
	
	$mail_body += "Users with leak passwords:`n"
	$mail_body += "$users_with_leak_passwords`n`n"
	
	$mail_body += "Users sharing passwords:`n"
	
	$temp_counter = 0

	foreach ($password in $shared_passwords_present)
	{
		$mail_body += "$((++$temp_counter)) : $password`n"
	}
	
	Send-MailMessage -From $mail_sender -To $mail_recipient -Subject $mail_subject -Body $mail_body -SmtpServer $mail_smtp -Attachments $log_filename
}
else
{
	Log-Automatic -string "The AD returned no users - no comparisons can be performed." -type 'fail' -timestamp
}
exit
