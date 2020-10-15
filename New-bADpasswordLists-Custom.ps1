# A really simple PoC-script to generate lists with bad/weak passwords
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

$years = (0..9 | foreach{ $_ }) + 00..99 | foreach { $_.ToString("00") }) + (1950..2021 | foreach { $_.ToString() })
$permutations = @("", ".", "!", "?", "=", ".!", "..", "!!", "!.", "?.", ".=")

$strings = @('company name')

# =========================
# PERFORM GENERATION
# =========================

$filename = "weak-passwords-custom.txt"
[System.Collections.ArrayList]$weak = @()

foreach ($string in $strings) {
    $weak.Add("$string") > $null
    $weak.Add("$($string.ToLower())") > $null
    $weak.Add("$($string.ToUpper())") > $null
    
    foreach ($year in $years) {
        foreach ($permutation in $permutations) {
            $weak.Add("$string$year$permutation") > $null
            $weak.Add("$($string.ToLower())$year$permutation") > $null
            $weak.Add("$($string.ToUpper())$year$permutation") > $null
        }
    }
}

$weak | Set-Content ".\$filename"