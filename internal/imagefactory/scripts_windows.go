//go:build windows

package imagefactory

import (
	"encoding/binary"
	"encoding/json"
)

// Only deliberate Console writes belong to the result channel. PowerShell's
// success and host streams (including module initialization) are incidental.
// Explicit stream-1 redirection also discards output when a script calls exit;
// assignment to $null alone does not reliably consume that pipeline on PS 5.1.
// An invoked .ps1's exit ends that file, not this process. Reset and propagate
// its LASTEXITCODE; terminating errors still map to the fixed bootstrap step 18.
const guestBootstrap = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);function Write-SpikeStep([int]$s){};function Read-Frame([int]$n){$b=New-Object byte[] $n;$o=0;while($o -lt $n){$r=$i.Read($b,$o,[Math]::Min(4096,$n-$o));if($r -le 0){throw 'frame'};$o+=$r};return ,$b};try{$i=[Console]::OpenStandardInput();$n=[BitConverter]::ToUInt32((Read-Frame 4),0);if(!$n -or $n -gt 65536){exit 18};$p=[Text.Encoding]::UTF8.GetString((Read-Frame $n))|ConvertFrom-Json;$global:LASTEXITCODE=0;$null = & ([ScriptBlock]::Create($p.script)) $p.data 1>$null 3>$null 4>$null 5>$null 6>$null;exit [int]$global:LASTEXITCODE}catch{exit 18}`
const validateEntry = `param($data);$f=Join-Path 'C:\ProgramData\Bivouac\Image' 'hcs-spike-validate.ps1';if((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $data.script_sha256){exit 14};& $f $data`
const sanitizeEntry = `param($data);$f=Join-Path 'C:\ProgramData\Bivouac\Image' 'hcs-spike-sanitize.ps1';if((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $data.sanitize_sha256){exit 14};& $f $data`

func guestInput(script string, data any) ([]byte, error) {
	b, err := json.Marshal(map[string]any{"script": script, "data": data})
	if err != nil {
		return nil, err
	}
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(b))), b...), nil // #nosec G115 -- fixed scripts and bounded configuration keep this below 64 KiB.
}
