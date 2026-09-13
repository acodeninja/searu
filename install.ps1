#Requires -Version 5.1
# Install searu on Windows: fetch a prebuilt binary for this machine, or build from source where
# none is published. Usage: irm .../install.ps1 | iex   (set $env:SEARU_VERSION=vX.Y.Z to pin a
# release, $env:SEARU_BIN_DIR to change where the binary lands.)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function say  { param($m) Write-Host $m }
function warn { param($m) Write-Warning $m }
function die  { param($m) Write-Error $m; exit 1 }
function have { param($c) [bool](Get-Command $c -ErrorAction SilentlyContinue) }

$repo    = 'acodeninja/searu'
$gitUrl  = "https://github.com/$repo.git"
$version = $env:SEARU_VERSION
$binDir  = if ($env:SEARU_BIN_DIR) { $env:SEARU_BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\searu' }

function Add-ToUserPath {
    param($dir)
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) { $entries = $userPath -split ';' | Where-Object { $_ -ne '' } }
    if ($entries | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') }) {
        say "$dir is already on your user PATH."
    } else {
        $updated = (@($entries) + $dir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
        say "Added $dir to your user PATH; new shells will pick it up automatically."
    }
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') })) {
        $env:Path = "$dir;$env:Path"
    }
}

function Complete-Install {
    param($where, [switch]$Cargo)
    if ($Cargo) {
        if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $where.TrimEnd('\') })) {
            warn "$where is not on your PATH; add it so you can run searu."
        }
    } else {
        Add-ToUserPath $where
    }
    if (-not (have docker)) { warn "Docker was not found on PATH. searu needs Docker to run its tools." }
    say 'Done. Try: searu tool list'
    exit 0
}

function Install-FromSource {
    param($reason)
    say "No prebuilt binary for ${reason}; building from source."
    if (-not (have cargo)) { die 'cargo not found. Install Rust from https://rustup.rs and re-run.' }
    if ($version) {
        cargo install --git $gitUrl searu --tag $version --locked
    } else {
        cargo install --git $gitUrl searu --locked
    }
    if ($LASTEXITCODE -ne 0) { die 'cargo install failed.' }
    say 'Installed searu with cargo (typically ~\.cargo\bin).'
    Complete-Install (Join-Path $env:USERPROFILE '.cargo\bin') -Cargo
}

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }

switch ($arch) {
    'AMD64' { $target = 'x86_64-pc-windows-gnu'; $bin = 'searu.exe' }
    default { Install-FromSource "windows/$arch" }
}

$asset = "searu-$target.zip"
$base  = if ($version) { "https://github.com/$repo/releases/download/$version" }
         else          { "https://github.com/$repo/releases/latest/download" }

$tmp = Join-Path $env:TEMP "searu-install-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $zip = Join-Path $tmp $asset
    say "Downloading $asset ..."
    try { Invoke-WebRequest -Uri "$base/$asset" -OutFile $zip }
    catch { die "download failed: $base/$asset" }

    $sumFile = "$zip.sha256"
    try { Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $sumFile } catch { $sumFile = $null }
    if ($sumFile -and (Test-Path $sumFile)) {
        $expected = ((Get-Content $sumFile -Raw).Trim() -split '\s+')[0]
        $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash
        if ($expected -and ($expected -ine $actual)) { die "checksum mismatch for $asset" }
    }

    say 'Extracting ...'
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $exe = Join-Path $tmp $bin
    if (-not (Test-Path $exe)) { die "$bin not found in $asset" }

    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $binDir $bin) -Force
    say "Installed $(Join-Path $binDir $bin)"
}
finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Complete-Install $binDir
