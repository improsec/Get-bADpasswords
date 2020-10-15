# A really simple PoC-script to generate lists with bad/weak passwords
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

$locale = "da"

$years = (0..9 | foreach{ $_ }) + (00..99 | foreach { $_.ToString("00") }) + (1950..2021 | foreach { $_.ToString() }) + @("123", "1234", "12345")
$permutations = @("", ".", "!", "?", "=", ".!", "..", "!!", "!.", "?.", ".=")

$strings = @("Velkommen","Farvel","Vinter",[Regex]::Unescape("For\u00e5r"),"Foraar","Sommer",[Regex]::Unescape("Efter\u00e5r"),"Efteraar","Januar","Februar","Marts","April","Maj","Juni","Juli","August","September","Oktober","November","December","Mandag","Tirsdag","Onsdag","Torsdag","Fredag",[Regex]::Unescape("L\u00f8rdag"),"Loerdag",[Regex]::Unescape("S\u00f8ndag"),"Soendag")

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

$weak | Set-Content ".\$filename" -Encoding "UTF8"