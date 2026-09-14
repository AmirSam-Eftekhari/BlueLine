@echo off
REM BlueLine Windows packaging script.
REM Run this ON WINDOWS, from the project root, in a terminal with Python
REM on PATH. This project was built in a Linux sandbox with no Windows/
REM mingw toolchain and no network access to pyinstaller/pywebview, so
REM this script could be written and reviewed there but never executed.
REM Run it here and report back anything that doesn't match if you hit
REM an issue — the .spec file is a normal, inspectable PyInstaller spec.

echo === BlueLine Windows build ===

python -m venv .venv-build
call .venv-build\Scripts\activate.bat

echo Installing runtime dependencies...
pip install -r requirements.txt

echo Installing packaging dependencies...
pip install pyinstaller pywebview

echo Running the test suite before packaging (a broken build should never ship)...
python -m unittest discover -s tests
if %errorlevel% neq 0 (
    echo Tests failed — aborting build.
    exit /b 1
)

echo Building the .exe with PyInstaller (single-file build)...
pyinstaller packaging\blueline.spec --noconfirm

echo.
echo === Build complete ===
echo Your application is the single file: dist\BlueLine.exe
echo That one file is fully standalone — copy it anywhere and run it directly.
echo Scan history is stored in your user data folder (%%LOCALAPPDATA%%\BlueLine),
echo never next to the exe, so the exe itself never needs write access to its own folder.
