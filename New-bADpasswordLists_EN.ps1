# A really simple PoC-script to generate lists with bad/weak passwords
#
# Find us here:
# - https://www.improsec.com
# - https://github.com/improsec
# - https://twitter.com/improsec
# - https://www.facebook.com/improsec

$strNamesGeneral = @("Test", "Qwerty", "Qwert", "Qwer", 'Pa$$W0rd', "P@ssword", "P@ssw0rd", 'Pa$$word', "Passw0rd", "Password", "Welcome", "Start", "Summer", "Winter", "Autumn", "Spring", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December", "Monday", "Tueday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
$strNamesCustom = @("CustomXXX","CustomXXX","CustomXXX", "CustomXXX", "CustomXXX", "CustomXXX", "CustomXXX", "CustomXXX")

$strYears = @("0", "1", "2", "123", "1234", "09", "10", "11", "12", "13", "14", "15", "16", "18", "19", "20", "2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019", "2020")
$strPermuts = @("", ".", "!", "?", "=", ".!", "..", "!!", "!.", "?.", ".=")

$fileNameGeneral = "BadPasswords.txt"
$fileNameCustom  = "BadCustom.txt"
$arrBadPwdGeneral = @()
$arrBadPwdCustom = @()

ForEach($Names in $strNamesGeneral)
{
   ForEach($Years in $strYears)
   {
        ForEach($Permuts in $strPermuts)
        {
            $arrBadPwdGeneral += "$Names$Years$Permuts"
        }
   } 
}

ForEach($Names in $strNamesCustom)
{
   ForEach($Years in $strYears)
   {
        ForEach($Permuts in $strPermuts)
        {
            $arrBadPwdCustom += "$Names$Years$Permuts"
        }
   } 
}


$arrBadPwdGeneral | Set-Content ".\Accessible\Wordlists\$fileNameGeneral"
$arrBadPwdCustom | Set-Content ".\Accessible\Wordlists\$fileNameCustom"
