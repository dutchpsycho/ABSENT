$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$releaseDir = Join-Path $scriptDir "target/release"

if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    $installRust = Read-Host "Rust is not installed. Install Rust? (y/n)"
    if ($installRust -ne "y") {
        Write-Host "Aborted."
        exit
    }

    Write-Host "Installing Rust..."
    Invoke-WebRequest -Uri "https://win.rustup.rs" -OutFile "rustup-init.exe"
    Start-Process -FilePath ".\rustup-init.exe" -ArgumentList "-y" -Wait
    Remove-Item "rustup-init.exe" -Force

    $env:PATH += ";$env:USERPROFILE\.cargo\bin"
}

$rustupToolchain = & rustup show active-toolchain 2>$null
if ($rustupToolchain -notmatch "nightly") {
    Write-Host "Switching to nightly toolchain..."
    Start-Process -FilePath "rustup" -ArgumentList "install nightly" -NoNewWindow -Wait
    Start-Process -FilePath "rustup" -ArgumentList "default nightly" -NoNewWindow -Wait
}

$buildSuccess = $false
try {
    Start-Process -NoNewWindow -Wait -FilePath "cmd.exe" -ArgumentList "/c title ABSENT MGR && cargo build --release"
    $buildSuccess = $true
} catch {
    Write-Host "Build failed. Not opening target/release."
}

if ($buildSuccess -and (Test-Path $releaseDir)) {
    Start-Process explorer.exe -ArgumentList "`"$releaseDir`""
}