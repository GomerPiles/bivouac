package imagefactory

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"unicode/utf16"
)

// Embedded scripts are emitted as constants to keep all runtime state owned.
//go:generate go run ./scriptgen

func encodedPowerShell(s string) string {
	words := utf16.Encode([]rune(s))
	b := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[i*2:], w)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func unattended(name, user, password string) string {
	boot := encodedPowerShell(`$ErrorActionPreference='Stop';$d=Get-Volume | Where-Object FileSystemLabel -eq 'HCSSETUP' | Select-Object -First 1;if(!$d.DriveLetter){exit 1};& (Join-Path ($d.DriveLetter+':\') 'SETUP.PS1')`)
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
<settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><ComputerName>%s</ComputerName></component><component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Windows\Panther\Unattend\specialize.ps1</Path></RunSynchronousCommand></RunSynchronous></component></settings>
<settings pass="oobeSystem"><component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
<UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>%s</Name><Group>Administrators</Group><Password><Value>%s</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
<AutoLogon><Enabled>true</Enabled><Username>%s</Username><Password><Value>%s</Value><PlainText>true</PlainText></Password><LogonCount>1</LogonCount></AutoLogon>
<FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><Description>Initialize disposable HCS guest</Description><CommandLine>powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s</CommandLine><RequiresUserInput>false</RequiresUserInput></SynchronousCommand></FirstLogonCommands>
</component></settings></unattend>`, xmlText(name), xmlText(user), xmlText(password), xmlText(user), xmlText(password), boot)
}

func mediaScripts() map[string]string {
	return map[string]string{"SETUP.PS1": videoFacts + guestVideo + guestSetup, "HCSRUNNER.PS1": runnerExtract, "HCSVALIDATE.PS1": guestValidate, "HCSSANITIZE.PS1": imageSanitize, "HCSLOGON.PS1": autologonSecret, "HCSCHECK.PS1": runnerCheck}
}
