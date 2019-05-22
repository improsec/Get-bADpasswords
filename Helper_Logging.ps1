# Helper functions for logging
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

# ================ #
# FUNCTIONS =====> #
# ================ #

function Log-Specific {
    param (
		# full path to the destination file for logging
        [Parameter(Mandatory=$true)]
		[string] 	
		$filename,
		
		# string to output to the log-file
		[Parameter(Mandatory=$true)]
		[string] 	
		$string,		
		
		# information-type of the output string
		[ValidateSet("info", "data", "fail")]
		[string] 	
		$type,				
			
		# whether to log with time-stamp or not
		[switch]	
		$timestamp
    )
	
	if ($PSBoundParameters.ContainsKey('type'))	{
		if ($timestamp) {
			$now = Get-Date -Format dd.MM.yyyy-HH:mm:ss
			Add-content -Path $filename -Value "$now`t$type`t$string"
		} else {
			Add-content -Path $filename -Value "$type`t$string"
		}
	} else {
		if ($timestamp) {
			$now = Get-Date -Format dd.MM.yyyy-HH:mm:ss
			Add-content -Path $filename -Value "$now`t$string"
		} else {
			Add-content -Path $filename -Value "$string"
		}
	}
}

function Log-Automatic {
	param (
		# string to output to the log-file
		[Parameter(Mandatory=$true)]
		[string] 	
		$string,		
		
		# information-type of the output string
		[ValidateSet("info", "data", "fail")]
		[string] 	
		$type,				
			
		# whether to log with time-stamp or not
		[switch]	
		$timestamp	
	)
	
	Write-Host -Object $string
	
	if ($write_to_log_file) {
		if ($PSBoundParameters.ContainsKey('type')) {
			if ($timestamp) {
				Log-Specific -filename $log_filename -string $string -type $type -timestamp
			} else {
				Log-Specific -filename $log_filename -string $string -type $type
			}
		} else {
			if ($timestamp) {
				Log-Specific -filename $log_filename -string $string -timestamp
			} else {
				Log-Specific -filename $log_filename -string $string
			}
		}
	}
}