# A few helper functions
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

# ================ #
# CONFIGURATION => #
# ================ #

# Domain information
$domain_name = "YourDomainName"
$naming_context = 'DC=domain,DC=com'

# Directories
$group_folder = '.\Accessible\AccountGroups'
$password_folder = '.\Accessible\PasswordLists'

# Logging
$current_timestamp = Get-Date -Format ddMMyyyy-HHmmss

$log_filename  = ".\Accessible\Logs\log_$domain_name-$current_timestamp.txt"
$csv_filename  = ".\Accessible\CSVs\exported_$domain_name-$current_timestamp.csv"

$event_log = "Improsec Password Audit"
$event_source = "Improsec"

$write_to_log_file = $true
$write_to_csv_file = $true
$write_to_eventlog = $false
$write_hash_to_logs = $false

# Result email dispatch information
$mail_smtp = "mail-smtp.yourcompany.com"
$mail_recipient = "Get-bADpassword <badpwd@yourcompany.com>"
$mail_sender = "Get-bADpasswords <badpwd@yourcompany.com>"
$mail_subject = "Get-bADpasswords $($domain_name.ToUpper()) $current_timestamp"

$send_log_file = $true
$send_csv_file = $true

# ================ #
# PREPROCESSING => #
# ================ #

if ($write_to_eventlog) {
    New-EventLog -Source $event_source -LogName $event_log > $null
}

$current_directory = Split-Path $MyInvocation.MyCommand.Path
[System.IO.Directory]::SetCurrentDirectory($current_directory) > $null

[System.IO.Directory]::CreateDirectory('.\Accessible\Logs') > $null
[System.IO.Directory]::CreateDirectory('.\Accessible\CSVs') > $null

$psi_library_path = '.\\PSI\\'
$psi_repacker_path = '.\PSI\'

if ([System.Environment]::Is64BitOperatingSystem -and [System.Environment]::Is64BitProcess) {
	$psi_library_path += 'Psi_x64.dll'
	$psi_repacker_path += 'PsiRepacker_x64.exe'
} else {
	$psi_library_path += 'Psi_x86.dll'
	$psi_repacker_path += 'PsiRepacker_x86.exe'
}

# include helper files
. '.\Helper_Logging.ps1'
. '.\Helper_Passwords.ps1'

# ================ #
# VARIABLES =====> #
# ================ #

# constant(s)
$empty_nt_hash = '31d6cfe0d16ae931b73c59d7e0c089c0'
                  
# miscellaneous
$script_name = 'Get-bADpasswords'
$script_version = '3.00'

# ================ #
# FUNCTIONS =====> #
# ================ #

function Get-AliveDomainController {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        $name
    )

    $context_type = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
    $domain_context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new($context_type, $name);
    $domain_controllers = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($domain_context).FindAllDomainControllers();

    if (!($domain_controllers)) {
        return $null
    } else {
        foreach ($domain_controller in $domain_controllers) {
            if (Test-Connection $domain_controller.Name -Count 1) {
                return $domain_controller.Name
            }
        }
    }
}

# ================ #
# SCRIPT ========> #
# ================ #

clear

Log-Automatic -string "Version:`t'$script_name v$script_version'." -type 'info' -timestamp
Log-Automatic -string "Log file:`t'$log_filename'." -type 'info' -timestamp
Log-Automatic -string "CSV file:`t'$csv_filename'." -type 'info' -timestamp

Log-Specific -filename $csv_filename -string "sep=;"

if ($write_hash_to_logs) {
    Log-Specific -filename $csv_filename -string "Activity;Password Type;Account Type;Account Name;Account SID;Enabled;Path;Account password hash;Present in password list(s)"
} else {
    Log-Specific -filename $csv_filename -string "Activity;Password Type;Account Type;Account Name;Account SID;Enabled;Path;Present in password list(s)"
}

# =========== Query domain data ===========
$domain_controller_fqdn = Get-AliveDomainController -name $domain_name

if (!($domain_controller_fqdn)) {
    Log-Automatic -string "A live Domain Controller in '$domain_name' was not found. Exiting." -type 'info' -timestamp
    exit
}

$domain_controller = $domain_controller_fqdn.Split('.')[0]

# =========== Repack password files ===========
Log-Automatic -string "Testing versioning for files in '$password_folder'..." -type 'info' -timestamp
Get-RepackFiles -files (Get-ChildItem $password_folder -Filter '*.txt')

# =========== Query AD user data ===========
Log-Automatic -string "Replicating AD user data with parameters (DC = '$domain_controller', NC = '$naming_context')..." -type 'info' -timestamp

$ad_users = $null

try {
    $ad_users = Get-ADReplAccount -All -Server $domain_controller -NamingContext $naming_context | where { $_.SamAccountType -eq 'User' } | select SamAccountName,DistinguishedName,SID,Enabled,@{ N="NtHash"; E={ ConvertTo-Hex $_.NTHash }},@{ N="Path"; E={ '' }},@{ N="Activity"; E={ if ($_.Enabled) { 'active' } else { 'inactive' } }},@{ N="PrivilegeType"; E={ 'regular' }}
} catch {
    Log-Automatic -string $_.Exception.Message -type 'fail' -timestamp
    exit
}

if (($ad_users -eq $null) -or ($ad_users.Count -le 0)) {
    Log-Automatic -string "The AD returned no users - no comparisons can be performed." -type 'fail' -timestamp
    exit
} else {
    Log-Automatic -string "The AD returned $($ad_users.count) users." -type 'info' -timestamp
    
    foreach ($user in $ad_users) {
        $tmp = Get-ADUser $user.Sid -Properties AccountExpirationDate,CanonicalName
        $user.Path = $tmp.CanonicalName

        if (($user.Enabled) -and ($tmp -ne $null) -and ($tmp.AccountExpirationDate -ne $null) -and ($tmp.AccountExpirationDate -le (Get-Date))) {
            $user.Activity = 'inactive'
        }
    }

    foreach ($group_file in (Get-ChildItem $group_folder -Filter '*.txt')) {
	foreach ($group in (Get-Content -Path $group_file.FullName)) {
	    $group_identity = ($group_file.BaseName -split ' - ')[1].ToLower()
	    $members = Get-ADGroupMember -Identity $group -Recursive | select -ExpandProperty SID

	    foreach ($user in $ad_users) {
		if (($members -contains $user.SID) -and ($user.PrivilegeType -eq 'regular')) {
		    $user.PrivilegeType = $group_identity
		}
	    }
	}
    }
}

# =========== Test for empty / weak passwords ===========
$users_with_empty_password = @($ad_users | where { ($_.NtHash -ne $null) -and ($_.NtHash -eq $empty_nt_hash) })
$users_with_valid_password = @($ad_users | where { ($_.NtHash -ne $null) -and ($_.NtHash -ne $empty_nt_hash) })

[System.Collections.ArrayList]$user_hashes = @()

foreach ($user in $users_with_valid_password) {
    if ($user_hashes.Contains($user.NtHash) -eq $false) {
        $user_hashes.Add($user.NtHash) > $null
    }
}

$files = (Get-ChildItem $password_folder -Filter '*.bin').FullName
$results = @()

Test-Passwords -sources $files -hashes $user_hashes -results ([ref]$results) > $null

$user_matches = @()

foreach ($result in $results) {
    $pair = $result -split '\;'
    $user_matches += @($users_with_valid_password | where { $_.NtHash -eq $pair[0] } | select Enabled,Activity,PrivilegeType,SamAccountName,SID,NtHash,Path,@{ N="PasswordFiles"; E={ @($pair[1] -split '\|') }})
}

$file_matches = @{}

foreach ($user in $user_matches) {
    foreach ($file in $user.PasswordFiles) {
        $filename = (Get-Item -Path $file).BaseName

        if ($file_matches.Keys -notcontains $filename) {
            $file_matches[$filename] = @()
        }
        
        $file_matches[$filename] += @($user)
    }
}

# =========== Test for shared passwords ===========
$shared_passwords = $users_with_valid_password | group -Property NtHash | where { $_.Count -gt 1 } | sort -Descending -Property Count | select Count,@{N="Enabled";E={ $_.Group.Enabled }},@{N="Activity";E={ $_.Group.Activity }},@{N="PrivilegeType";E={ $_.Group.PrivilegeType }},@{N="SamAccountName";E={ $_.Group.SamAccountName }},@{N="SID";E={ $_.Group.SID }},@{N="NtHash";E={ $_.Group.NtHash }},@{N="Path";E={ $_.Group.Path }}
$shared_passwords_info = $shared_passwords | measure -Property Count -Sum

# =========== Report results ===========
if (($users_with_empty_password -ne $null) -and ($users_with_empty_password.Count -gt 0)) {
	Log-Automatic -string "Found $($users_with_empty_password.Count) user(s) with empty passwords." -type 'info' -timestamp

    foreach ($user in $users_with_empty_password) {
        Log-Automatic -string "Empty password found for user '$($user.SamAccountName)'." -type 'info' -timestamp

	    if ($write_to_csv_file) {
            Log-Specific -filename $csv_filename -string "$($user.Activity);empty;$($user.PrivilegeType);$($user.SamAccountName);$($user.SID);$($user.Enabled);$($user.Path)"
	    }

        if ($write_to_eventlog) {
            Write-EventLog -Source $event_source -LogName $event_log -EntryType Warning -EventID 13371 -Message "Empty password found for user: $($user.SamAccountName)"
        }
    }
}

if (($user_matches -ne $null) -and ($user_matches.Count -gt 0)) {
    Log-Automatic -string "Found $($user_matches.Count) user(s) with weak passwords." -type 'info' -timestamp

    foreach ($user in $user_matches) {
        $files = "'$((Get-Item -Path $user.PasswordFiles).BaseName -join ""','"")'"
        Log-Automatic -string "Matched password found for user '$($user.SamAccountName)' in list(s) $files." -type 'info' -timestamp

        if ($write_to_csv_file) {
            if ($write_hash_to_logs) {
                Log-Specific -filename $csv_filename -string "$($user.Activity);weak;$($user.PrivilegeType);$($user.SamAccountName);$($user.SID);$($user.Enabled);$($user.Path);$($user.NtHash);$files"
            } else {
                Log-Specific -filename $csv_filename -string "$($user.Activity);weak;$($user.PrivilegeType);$($user.SamAccountName);$($user.SID);$($user.Enabled);$($user.Path);$files"
            }
        }

        if ($write_to_eventlog) {
            Write-EventLog -Source $event_source -LogName $event_log -EntryType Warning -EventID 13372 -Message "Weak password found for user: $($user.SamAccountName)"
        }
    }
}

if (($shared_passwords -ne $null) -and ($shared_passwords.Count -gt 0)) {
    Log-Automatic -string "Found $($shared_passwords_info.Sum) user(s) sharing $($shared_passwords_info.Count) passwords." -type 'info' -timestamp

    $tmp = 1
	
    foreach ($password in $shared_passwords) {
        $names = "'$($password.SamAccountName -join ""','"")'"

        if ($write_hash_to_logs) {
            Log-Automatic -string "Hash '$($password.NtHash)' is shared by user(s): $names." -type 'info' -timestamp
        } else {
            Log-Automatic -string "A single hash is shared by user(s): $names." -type 'info' -timestamp
        }

        if ($write_to_csv_file) {
            for ($i = 0; $i -lt $password.Count; $i++) {
                if ($write_hash_to_logs) {
                    Log-Specific -filename $csv_filename -string "$($password.Activity[$i]);shared;$($password.PrivilegeType[$i]);$($password.SamAccountName[$i]);$($password.SID[$i]);$($password.Enabled[$i]);$($password.Path[$i]);$($password.NtHash);$tmp"
                } else {
                    Log-Specific -filename $csv_filename -string "$($password.Activity[$i]);shared;$($password.PrivilegeType[$i]);$($password.SamAccountName[$i]);$($password.SID[$i]);$($password.Enabled[$i]);$($password.Path[$i]);$tmp"
                }
            }
        }

        if ($write_to_eventlog) {
            Write-EventLog -Source $event_source -LogName $event_log -EntryType Warning -EventID 13373 -Message "A single password is shared by users: $names"
        }
	
        $tmp++;
    }
}

Log-Automatic -string "Found a total of '$($users_with_empty_password.Count)' user(s) with empty passwords" -type 'info' -timestamp
Log-Automatic -string "Found a total of '$($user_matches.Count)' user(s) with weak passwords" -type 'info' -timestamp
Log-Automatic -string "Found a total of '$($shared_passwords_info.Sum)' user(s) with shared passwords" -type 'info' -timestamp

# =========== Dispatch email results ===========
$mail_body = "Total users: '$($ad_users.count)'`n"
$mail_body += "Amount of total users found with empty passwords: '$($users_with_empty_password.Count)' ($([Math]::round(($users_with_empty_password.Count / $ad_users.Count) * 100, 2))%)`n"
$mail_body += "Amount of total users found with weak passwords: '$($user_matches.Count)' ($([Math]::round(($user_matches.Count / $ad_users.Count) * 100, 2))%)`n"

foreach ($file in $file_matches.GetEnumerator()) {
    $mail_body += "`tFrom password list '$($file.Name)': $($file.Value.Count)`n"
}

$mail_body += "Number of total users sharing passwords: '$($shared_passwords_info.Sum)' ($([Math]::round(($shared_passwords_info.Sum / $ad_users.Count) * 100, 2))%)`n"
$mail_body += "Number of total unique passwords shared: '$($shared_passwords_info.Count)'`n`n"

# =========== Active / Inactive users ===========
$active_shared = 0
$inactive_shared = 0

foreach ($password in $shared_passwords) {
    for ($i = 0; $i -lt $password.Count; $i++) {
        if ($password.Enabled[$i] -eq $true) {
            $active_shared = $active_shared + 1
        } else {
            $inactive_shared = $inactive_shared + 1
        }
    }
}

# =========== Active users ===========
$active_empty = @($users_with_empty_password | where { $_.Enabled -eq $true })
$active_match = @($user_matches | where { $_.Enabled -eq $true })

$mail_body += "Total active users: '$(($ad_users | where { $_.Enabled -eq $true }).count)'`n"
$mail_body += "Amount of active users found with empty passwords: '$($active_empty.Count)' ($([Math]::round(($active_empty.Count / $ad_users.Count) * 100, 2))%)`n"
$mail_body += "Amount of active users found with weak passwords: '$($active_match.Count)' ($([Math]::round(($active_match.Count / $ad_users.Count) * 100, 2))%)`n"

foreach ($file in $file_matches.GetEnumerator()) {
    $active_file = @($file.Value | where { $_.Enabled -eq $true })

    if ($active_file.Count -gt 0) {
        $mail_body += "`tFrom password list '$($file.Name)': $($active_file.Count)`n"
    }
}

$mail_body += "Number of active users sharing passwords: '$($active_shared)' ($([Math]::round(($active_shared / $ad_users.Count) * 100, 2))%)`n`n"

# =========== Inactive users ===========
$inactive_empty = @($users_with_empty_password | where { $_.Enabled -eq $false })
$inactive_match = @($user_matches | where { $_.Enabled -eq $false })

$mail_body += "Total inactive users: '$(($ad_users | where { $_.Enabled -eq $false }).count)'`n"
$mail_body += "Amount of active users found with empty passwords: '$($inactive_empty.Count)' ($([Math]::round(($inactive_empty.Count / $ad_users.Count) * 100, 2))%)`n"
$mail_body += "Amount of active users found with weak passwords: '$($inactive_match.Count)' ($([Math]::round(($inactive_match.Count / $ad_users.Count) * 100, 2))%)`n"

foreach ($file in $file_matches.GetEnumerator()) {
    $inactive_file = @($file.Value | where { $_.Enabled -eq $false })

    if ($inactive_file.Count -gt 0) {
        $mail_body += "`tFrom password list '$($file.Name)': $($inactive_file.Count)`n"
    }
}

$mail_body += "Number of inactive users sharing passwords: '$($inactive_shared)' ($([Math]::round(($inactive_shared / $ad_users.Count) * 100, 2))%)`n`n"

# =========== Shared passwords ===========
if (($users_with_empty_password -ne $null) -and ($users_with_empty_password.Count -gt 0)) {
    $mail_body += "Users with empty passwords:`n"
    $mail_body += "$($users_with_empty_password.SamAccountName -join ""`n"")`n`n"
}

if (($user_matches -ne $null) -and ($user_matches.Count -gt 0)) {
    $mail_body += "Users with weak passwords:`n"
    $mail_body += "$($user_matches.SamAccountName -join ""`n"")`n`n"
}

if (($shared_passwords -ne $null) -and ($shared_passwords.Count -gt 0)) {
    $mail_body += "Users with shared passwords:`n"

    $tmp = 1

    foreach ($password in $shared_passwords) {
        $mail_body += "$($tmp): '$($password.SamAccountName -join ""','"")'`n"
        $tmp++;
    }
}

$attachments = @()

if ($send_log_file) {
    $attachments += $log_filename
}

if ($send_csv_file) {
    $attachments += $csv_filename
}

Send-MailMessage -From $mail_sender -To $mail_recipient -Subject $mail_subject -Body $mail_body -SmtpServer $mail_smtp -Attachments $attachments
exit
