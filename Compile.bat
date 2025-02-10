@echo off
setlocal enabledelayedexpansion

where /q rustc
if %errorlevel% neq 0 (
    echo Rust is not installed.
    set /p install_rust="Install rust? (y/n): "
    if /i "!install_rust!" neq "y" (
        echo Aborted.
        exit /b
    )

    echo Installing...
    powershell -Command "& {Invoke-WebRequest -Uri 'https://win.rustup.rs' -OutFile 'rustup-init.exe'}"
    start /wait rustup-init.exe -y
    del "rustup-init.exe"
    set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
)

rustup show active-toolchain | findstr /i "nightly" >nul
if %errorlevel% neq 0 (
    echo Switching to nightly toolchain...
    rustup install nightly
    rustup default nightly
)

start "ABSENT MGR" cmd /c "cargo build --release && start explorer target\release"