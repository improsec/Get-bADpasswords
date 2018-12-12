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
	[DllImport("$psi_library_name", CallingConvention = CallingConvention.StdCall)]
	public static extern void AddSource(string filename);
	
	[DllImport("$psi_library_name", CallingConvention = CallingConvention.StdCall)]
	public static extern void ClearSources();
	
	[DllImport("$psi_library_name", CallingConvention = CallingConvention.StdCall)]
	public static extern void TestHashes(string[] input, int count, [MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_BSTR)] out string[] output);
"@

$PsiTest = Add-Type -MemberDefinition $MethodDefinition -Name 'Test' -Namespace 'Psi' -PassThru

# ================ #
# FUNCTIONS =====> #
# ================ #

function Test-LeakPasswords
{
    Param
    (
		# string-array of source-files containing the leaked hashes
        [Parameter(Mandatory=$true)]
		[string[]]
		$sources,
		
		# string-array of hashes to compare against the leaked hashes
		[Parameter(Mandatory=$true)]
		[string[]]
		$user_hashes,
		
		# string-array to receive the matches
		[Parameter(Mandatory=$true)]
		[ref]
		$results
    )
	
	Log-Automatic -string "Testing user passwords against leaked passwords..." -type 'info' -timestamp
	
	foreach ($source in $sources)
	{
		if (Test-Path $source)
		{
			[Psi.Test]::AddSource($source)
		}
	}
	
	[Psi.Test]::TestHashes($user_hashes, $user_hashes.Count, $results)
	[Psi.Test]::ClearSources()
	
	Log-Automatic -string "Finished comparing passwords.`n" -type 'info' -timestamp
}