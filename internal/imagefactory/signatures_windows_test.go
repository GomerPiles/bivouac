//go:build windows

package imagefactory

import (
	"encoding/json"
	"testing"
)

func TestEmbeddedSignatures(t *testing.T) {
	input, _ := json.Marshal(map[string]string{"root": t.TempDir()})
	script := embeddedSignatures + `
$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json
Initialize-EmbeddedSignature
$source=Join-Path $env:SystemRoot 'Boot\EFI\bootmgfw.efi'
$bytes=[IO.File]::ReadAllBytes($source)
$parsed=[FactoryEmbeddedSignature]::Parse($bytes);$verified=Get-EmbeddedSignature $source
if($parsed[0] -lt 1 -or $parsed[0] -gt 4 -or $parsed[1] -lt 1 -or $verified.issuer -ne $parsed[0] -or $verified.signatures -ne $parsed[1]){throw 'system embedded signature'}
$bad=$bytes.Clone();$bad[0]=0
$truncated=[byte[]]$bytes[0..255]
$pe=[BitConverter]::ToUInt32($bytes,0x3c);$optional=$pe+24
$directory=$optional+112+32
$offset=[BitConverter]::ToUInt32($bytes,$directory);$length=[BitConverter]::ToUInt32($bytes,($directory+4))
$wrongOffset=$bytes.Clone();[BitConverter]::GetBytes([uint32]1).CopyTo($wrongOffset,$directory)
$wrongCert=$bytes.Clone();$wrongCert[$offset+6]=1
$malformed=$bytes.Clone();$malformed[$offset+8]=0
foreach($value in @($null,([byte[]]@()),$bad,$truncated,$wrongOffset,$wrongCert,$malformed,([byte[]]::new(33554433)))){
 $result=[FactoryEmbeddedSignature]::Parse($value)
 if($result[0] -ne 0 -or $result[1] -ne 0){throw 'malformed PE accepted'}
}
if($offset+$length -ne $bytes.Length){throw 'fixture certificate location'}
$multiple=[byte[]]::new($bytes.Length+$length);$bytes.CopyTo($multiple,0)
[Array]::Copy($bytes,$offset,$multiple,$bytes.Length,$length)
[BitConverter]::GetBytes([uint32]($length*2)).CopyTo($multiple,($directory+4))
$result=[FactoryEmbeddedSignature]::Parse($multiple)
if($result[0] -ne $parsed[0] -or $result[1] -ne ($parsed[1]*2)){throw 'embedded count/primary'}
$changed=$bytes.Clone();$changed[0x40]=$changed[0x40] -bxor 1
$path=Join-Path $data.root 'changed.efi';[IO.File]::WriteAllBytes($path,$changed)
$signature=Get-EmbeddedSignature $path
if($signature.issuer -ne 0){throw 'PE digest mismatch accepted'}
$copy=Join-Path $data.root 'copy.efi';[IO.File]::WriteAllBytes($copy,$bytes)
if(!(Test-BootFileMatch $copy $source) -or (Test-BootFileMatch $copy $path)){throw 'byte comparison'}
foreach($issuer in @(@('CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation',1),@('CN=Windows UEFI CA 2023, O=Microsoft Corporation',2),@('CN=Microsoft Windows Production PCA 2026, O=Microsoft Corporation',3),@('CN=Other',4))){
 if([FactoryEmbeddedSignature]::Issuer($issuer[0]) -ne $issuer[1]){throw 'issuer code'}
}
[Console]::Out.Write('embedded')`
	if got := runTestPS(t, script, input); got != "embedded" {
		t.Fatal("embedded signature parsing/trust", got)
	}
}
