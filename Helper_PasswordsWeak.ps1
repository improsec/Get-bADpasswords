# A few helper functions
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

# ================ #
# FUNCTIONS =====> #
# ================ #

function Get-NtHashFromPlainText
{
    Param 
	(
		[Parameter(Mandatory=$true)]
		[string]
		$plain_text
	)
	
	return ConvertTo-NTHash $(ConvertTo-SecureString -String $plain_text -AsPlainText -Force)
}

function Generate-WeakPasswords
{
	Param
	(
		# string-array of source-files containing the plain-text password parts
		[Parameter(Mandatory=$true)]
		[string[]]
		$sources,
		
		# hash-table to receive the keys
		[Parameter(Mandatory=$true)]
		[ref]
		$results
	)
	
	Log-Automatic -string "Loading weak password source files..." -type 'info' -timestamp
	
	$results.value.Clear()
	$results.value.Add($empty_nt_hash, '')
	
	foreach ($source in $sources)
	{
		Log-Automatic -string "Checking source file: '$source'." -type 'info' -timestamp
		
		if (Test-Path $source)
		{
			Log-Automatic -string "Source file found: '$source'." -type 'info' -timestamp
			
			$lines = 0
			$words = Get-Content -Path $source
			
			foreach ($word in $words)
			{
				$lines++;
				
				if ($word -eq '')
				{
					Log-Automatic -string "Empty input line ignored (line: '$lines')." -type 'info' -timestamp
				}
				else 
				{
					$nt_hash = $(Get-NtHashFromPlainText -plain_text $word)
					
					if ($results.value.ContainsKey($nt_hash))
					{
						Log-Automatic -string "Duplicate password: '$word' = '$nt_hash' (line: '$lines')." -type 'info' -timestamp
					}
					else
					{
						$results.value.Add($nt_hash, $word)
					}
				}
			}
		}
		else
		{
			Log-Automatic -string "Source file not found: '$source'." -type 'fail' -timestamp
		}
	}
	
	# Possibility : Log amount of entries/duplicates in the weak_hashes container.
	
	return ($results.value.count -gt 1) # One of the hashes was added by default (empty nt hash)
}

function Test-WeakPasswords
{
    Param
    (
		# string-array of user password hashes to be tested
		[Parameter(Mandatory=$true)]
		[string[]]
		$user_hashes,
		
		# hash-table of weak password hashes to compare against the user password hashes
		[Parameter(Mandatory=$true)]
		[ref]
		$weak_hashes
    )
	
	Log-Automatic -string "Testing user passwords against weak passwords..." -type 'info' -timestamp
	
	$results = @{}
	
	foreach ($hash in $user_hashes)
	{
		if ($weak_hashes.value.ContainsKey($hash))
		{
			if ($results.ContainsKey($hash) -eq $false)
			{
				$results.Add($hash, $weak_hashes.value.Item($hash))
			}
		}
	}	
	
	$weak_hashes.value = $results
	
	Log-Automatic -string "Finished comparing passwords.`n" -type 'info' -timestamp
}