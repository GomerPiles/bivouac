# Requests Administrator consent for the protected engine startup helper.
# Runs as the ordinary user and launches only the administrator-protected
# copy of Start-VMEngines.ps1 in -EngineDirectory; nothing from BIVOUAC_HOME
# reaches the elevated process. That helper verifies its own folder before
# trusting any input, so a copy in an unprotected folder refuses to run.
param(
    [string]$EngineDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'bivouac', 'engines')
)
$ErrorActionPreference = 'Stop'

$pwsh = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'PowerShell', '7', 'pwsh.exe')
$script = [IO.Path]::Combine($EngineDirectory, 'Start-VMEngines.ps1')

# ShellExecute takes one parameter string, which pwsh splits with the standard
# Windows command-line rules. Each argument is limited to a drive-qualified
# path of plain components (letters, digits, space, '.', '_', '-') or a
# letters-only switch or value. A path that contains no quote, wrapped in double quotes, is exactly
# one argument, and since it never ends in a backslash nothing can escape its
# closing quote. This also keeps the command line in the consent details readable.
function Assert-PlainPath([string]$Path) {
    if ($Path -cnotmatch '^[A-Za-z]:(\\[A-Za-z0-9 ._-]+)+$' -or $Path.Contains('..')) {
        throw "Unsupported characters in engine startup path: $Path"
    }
}
function Join-ShellArguments([string[]]$Arguments) {
    $quoted = foreach ($argument in $Arguments) {
        if ($argument -cmatch '^-?[A-Za-z]+$') {
            $argument
        } else {
            Assert-PlainPath $argument
            '"' + $argument + '"'
        }
    }
    $quoted -join ' '
}

Assert-PlainPath $pwsh
foreach ($path in @($pwsh, $script)) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Engine startup prerequisite missing: $path" }
}
$parameters = Join-ShellArguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script, '-Execute')

# Launch through the interactive desktop's Explorer (IShellDispatch2), so the
# elevated helper gets Explorer's launch context rather than this process's
# job; App Sandbox image operations need it. 8 = SWC_DESKTOP, 1 = SWFO_NEEDDISPATCH.
$shell = New-Object -ComObject Shell.Application
$location = 0
$root = 0
$handle = 0
$windows = $shell.Windows.Invoke()
$desktop = $windows.FindWindowSW([ref]$location, [ref]$root, 8, [ref]$handle, 1)
if (!$desktop) { throw 'Explorer desktop unavailable; start the helper from your interactive desktop' }
# 'runas' requests consent; 0 hides the helper's window.
$desktop.Document.Application.ShellExecute($pwsh, $parameters, $EngineDirectory, 'runas', 0)
Write-Output ('Approve the Administrator prompt for VM engines only if its details name ' + $script + '. Then use CI On. No startup task will be installed.')
