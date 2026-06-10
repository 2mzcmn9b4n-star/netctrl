@echo off
echo ============================================================
echo  NetCtrl - Build Standalone EXE
echo ============================================================

echo [1/3] Building Rust engine...
cd rust_engine
cargo build --release
if errorlevel 1 (
    echo [ERROR] Rust build failed. Make sure Rust is installed: https://rustup.rs
    pause
    exit /b 1
)
copy /Y target\release\rust_engine.exe ..\rust_engine.exe
cd ..

echo [2/3] Installing PyInstaller...
pip install pyinstaller

echo [3/3] Building Python EXE...
pyinstaller --onefile --noconsole --uac-admin ^
    --add-data "rust_engine.exe;." ^
    --add-data "device_names.json;." ^
    --name "NetCtrl" ^
    main.py

echo ============================================================
echo  Done! Find NetCtrl.exe in the dist/ folder.
echo  Run NetCtrl.exe as Administrator.
echo ============================================================
pause