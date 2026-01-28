# A really simple PoC-script to generate lists with bad/weak passwords
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

$locale = "common"

$current_year = (Get-Date).Year
$years = @(0..9 | ForEach-Object { $_.ToString() }) +
         @(0..99 | ForEach-Object { $_.ToString("00") }) +
         @(1950..$current_year | ForEach-Object { $_.ToString() }) +
         @("123","1234","12345")

$permutations = @("", ".", "!", "?", "=", ".!", "..", "!!", "!.", "?.", ".=")

$strings = @("Test","Qwerty","Qwert","Qwer","Password","Passw0rd","Pa`$`$word","Pa`$`$w0rd","Pa`$`$W0rd","P@ssword","P@ssw0rd","Welcome","Start","End")

# =========================
# PERFORM GENERATION
# =========================

$filename = "weak-passwords-$locale.txt"
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
