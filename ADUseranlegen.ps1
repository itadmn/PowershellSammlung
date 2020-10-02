#Dieses Script legt einen User in der Domain an und zusätzlich im Keepass
#RSAT Tools werden gebraucht
#Get-WindowsCapability -Online | ? {$_.Name -like "*RSAT*" -and $_.State -eq "NotPresent"} | Add-WindowsCapability -Online
#ToDo
#Schleife fuer AD Gruppen erweitern
#Mail bedingung erweitern
#Keepass check
#Keepass schleife fuer gruppe



###Parameter koennen beim Script Start mitgegeben werden
param (
[String]$Betrieb="",
[String]$Name="",
[String]$VorName="",
[String]$Mail
)

###Zufaeliges Passwort wird generiert
function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    return [String]$characters[$random]
}
 
function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString
}
$password = Get-RandomCharacters -length 6 -characters 'ABCDEFGHKLMNPQRSTUVWXYZ23456789'
$password = Scramble-String $password
$password = "*"+$password
 
#Write-Host $password

if ($Betrieb -eq ""){$Betrieb = Read-Host "Betriebsnummer"}
if ($Name -eq ""){$Name = Read-Host "Name"}
if ($VorName -eq ""){$VorName = Read-Host "VorName"}
if ($VorName -eq ""){$VorName = $Betrieb}

$AdminBenutzer = "" #ToDo Admin Benutzer eintragen, welcher den Benutzer in dem AD anlegt (z.B. Domänenadministrator -> domain\admin)
$ADhost = "" #ToDo IP-Adr. einfügen
$PasswortDatei = "D:\PasswortDatei.txt"


$pass = Get-Content $PasswortDatei | ConvertTo-SecureString
$LogIn = New-Object System.Management.Automation.PsCredential($AdminBenutzer, $pass)
$Fehler="true"
Try  { $Script:GetADUserResult =Get-ADUser -Identity $Betrieb$Name -Server $ADhost -credential $LogIn} Catch {$Fehler="false"}
if ($Fehler -eq "true"){write-Host "User exestiert schon"; exit}
$userpass= $password | ConvertTo-SecureString -AsPlainText -Force


$gruppe=Get-ADGroup -Filter "Name -like '$Betrieb*'" -Server $ADhost -credential $LogIn

if ($gruppe.count -ne 1)
{
    switch(Read-Host "`nEs gibt mehr als eine Gruppe: `n[0]" $gruppe[0].name "`n[1]"$gruppe[1].name"`nBitte wähle die richtige Gruppe aus")
    {
        0{$gruppe=$gruppe[0]; break}
        1{$gruppe=$gruppe[1]; break}
        default {"Ungültige Eingabe"; break}
    }
}
$neu=$gruppe.name


#####LoginScript#####
$LoginScript="***.cmd"
$LoginPath="\\******.local\NETLOGON\$Betrieb$LoginScript"
if (Invoke-Command -ComputerName $ADhost -ScriptBlock {Test-Path -path $args[0]} -argumentlist $LoginPath -credential $LogIn) {$LoginScript="$Betrieb$LoginScript"}
#####LoginScriptende#####



#####User wird angelegt und anschließend der Gruppe zugeordnet

if ($Mail -eq ""){
New-ADUser -SamAccountName $Betrieb$Name -CannotChangePassword $True -Surname $Name -GivenName $VorName -displayname "$VorName $Name" -Name "$VorName $Name" -UserPrincipalName "$Betrieb$Name@*******.local" -PasswordNeverExpires $True -ProfilePath \\*******\userprofiles\$Betrieb$Name -ScriptPath $LoginScript -Enabled $True -AccountPassword $userpass -Server $ADhost -credential $LogIn -Path "OU=$neu,DC=*********,DC=local";
Add-ADGroupMember -Identity $neu -Members $Betrieb$Name -Server $ADhost -credential $LogIn
}else{

}
#### User und Passwort werden ausgegeben
Write-Host "Username: " $Betrieb$Name
Write-Host "Passwort: " $password


$Ort="C:\Program Files (x86)\KeePass Password Safe 2\" 
(Get-ChildItem -recurse $Ort | Where-Object {($_.Extension -EQ ".dll") -or ($_.Extension -eq ".exe")} | ForEach-Object { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | out-null
$CompositeKey = New-Object -TypeName KeePassLib.Keys.CompositeKey
$KeePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
$KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($KeePassword)
$CompositeKey.AddUserKey( $KcpPassword )
$IOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
$IOConnectionInfo.Path = '\\*********.kdbx'
$StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
$PwDatabase = New-Object -TypeName KeePassLib.PwDatabase 
$PwDatabase.Open($IOConnectionInfo, $CompositeKey, $StatusLogger)

$neu = $PwDatabase.RootGroup.Groups.name -like "$Betrieb*"
$Title="$VorName $Name"
$UserName="$Betrieb$Name"
$Password="$password"

######Daten werden in Keepass geschieben

$PwGroup = @( $PwDatabase.RootGroup.Groups | where { $_.name -like $neu } )
if ($PwGroup.Count -eq 0) { throw "ERROR: $TopLevelGroupName group not found" ; return }
elseif ($PwGroup.Count -gt 1) { throw "ERROR: Multiple groups named $TopLevelGroupName" ; return }
$PwEntry = New-Object -TypeName KeePassLib.PwEntry( $PwGroup[0], $True, $True )
$pTitle = New-Object KeePassLib.Security.ProtectedString($True, $Title)
$pUser = New-Object KeePassLib.Security.ProtectedString($True, $UserName)
$pPW = New-Object KeePassLib.Security.ProtectedString($True, $Password)
$PwEntry.Strings.Set("Title", $pTitle)
$PwEntry.Strings.Set("UserName", $pUser)
$PwEntry.Strings.Set("Password", $pPW)
$PwGroup[0].AddEntry($PwEntry, $True)
$StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
$PwDatabase.Save($StatusLogger)
$PwDatabase.Close()


Write-Host "Ende"