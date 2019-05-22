# A few helper functions
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

# ================ #
# PREPROCESSING => #
# ================ #

$MethodDefinition = @"
	[DllImport("$psi_library_path", CallingConvention = CallingConvention.StdCall)]
	public static extern void AddSource(string filename);
	
	[DllImport("$psi_library_path", CallingConvention = CallingConvention.StdCall)]
	public static extern void ClearSources();
	
	[DllImport("$psi_library_path", CallingConvention = CallingConvention.StdCall)]
	public static extern void TestHashes(string[] input, int count, [MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_BSTR)] out string[] output);
"@

$PsiTest = Add-Type -MemberDefinition $MethodDefinition -Name 'Test' -Namespace 'Psi' -PassThru

# ================ #
# FUNCTIONS =====> #
# ================ #

function Get-FileChecksum {
    param (
		[Parameter(Mandatory=$true)]
		[String]
		$filepath
    )

    return (Get-FileHash -path $filepath -algorithm SHA256).Hash
}

function Get-ShouldRepack {
    param (
		[Parameter(Mandatory=$true)]
		[String]
		$filepath,
        
		[Parameter(Mandatory=$true)]
		[String]
        $checksum,
        
		[Parameter(Mandatory=$true)]
		[String]
        $repacked
    )
    
    if ([System.IO.File]::Exists($checksum) -and [System.IO.File]::Exists($repacked)) {
        $hash_filepath = Get-FileChecksum -filepath $filepath
        $hash_checksum = Get-Content -path $checksum
        
        return ($hash_filepath -ne $hash_checksum)
    } else {
        return $true
    }
}

function Get-RepackFiles {
    param (
        [Parameter(Mandatory=$true)]
		[System.IO.FileInfo[]]
		$files
    )
    
    foreach ($file in $files) {
        $checksum = "$($file.DirectoryName)\$($file.BaseName).chk"
        $repacked = "$($file.DirectoryName)\$($file.BaseName).bin"

        if (!(Get-ShouldRepack -filepath $file.FullName -checksum $checksum -repacked $repacked)) {
	        Log-Automatic -string "'$($file.Name)' repack is up to date..." -type 'info' -timestamp
        } else {
	        Log-Automatic -string "'$($file.Name)' repack is outdated. Repacking file..." -type 'info' -timestamp
            Set-Content -path $checksum -value $(Get-FileChecksum -filepath $file.FullName)
            Start-Process -NoNewWindow -FilePath "$psi_repacker_path" -ArgumentList @("`"$($file.FullName)`"","`"$repacked") -Wait
        }
    }
}

function Test-Passwords {
    param (
		# string-array of source-files containing the leaked hashes
        [Parameter(Mandatory=$true)]
		[string[]]
		$sources,
		
		# string-array of hashes to compare against the leaked hashes
		[Parameter(Mandatory=$true)]
		[string[]]
		$hashes,
		
		# string-array to receive the matches
		[Parameter(Mandatory=$true)]
		[ref]
		$results
    )
	
	Log-Automatic -string "Testing user passwords against password lists..." -type 'info' -timestamp
	
	foreach ($source in $sources) {
		if (Test-Path $source) {
			[Psi.Test]::AddSource($source)
		}
	}
	
	[Psi.Test]::TestHashes($hashes, $hashes.Count, $results)
	[Psi.Test]::ClearSources()
	
	Log-Automatic -string "Finished comparing passwords." -type 'info' -timestamp
}