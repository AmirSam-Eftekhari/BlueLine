@echo off
setlocal enabledelayedexpansion
REM BlueLine Windows packaging script.
REM Run this ON WINDOWS, from the project root, in a terminal with Python
REM on PATH. This project was built in a Linux sandbox with no Windows/
REM mingw toolchain, so this script is written and reviewed there but
REM never actually executed there — this version was rewritten after a
REM real user hit two bugs the first version had: (1) the .spec file
REM passed a `cipher=` parameter PyInstaller 6.0 removed, which crashed
REM before dist\ was created (fixed in blueline.spec — see the comment
REM at the top of that file), and (2) THIS script had no error checking
REM after most steps, so it printed "Build complete" even when a step
REM had silently failed. Both are fixed below: every step now checks its
REM own exit code and stops with a clear message instead of continuing.

echo === BlueLine Windows build ===
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: 'python' was not found on PATH. Install Python 3.10+ from
    echo python.org and make sure "Add python.exe to PATH" was checked
    echo during install, then re-run this script.
    exit /b 1
)

echo Python found:
python --version
echo.

echo Creating a clean build virtual environment...
if exist .venv-build (
    echo   .venv-build already exists, reusing it.
) else (
    python -m venv .venv-build
    if %errorlevel% neq 0 (
        echo ERROR: 'python -m venv' failed. Is your Python installation complete?
        exit /b 1
    )
)

call .venv-build\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ERROR: Could not activate .venv-build. Try deleting the .venv-build
    echo folder and running this script again.
    exit /b 1
)

echo.
echo Installing runtime dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: 'pip install -r requirements.txt' failed — see the error above.
    exit /b 1
)

echo.
echo Installing packaging dependencies (pyinstaller, pywebview)...
pip install -r packaging\requirements-packaging.txt
if %errorlevel% neq 0 (
    echo ERROR: Could not install pyinstaller/pywebview — see the error above.
    echo Common cause: no internet access, or a pip index that doesn't mirror
    echo these packages. Try 'pip install pyinstaller pywebview' by itself
    echo to see a more specific error.
    exit /b 1
)

echo.
echo pyinstaller version:
pyinstaller --version
if %errorlevel% neq 0 (
    echo ERROR: 'pyinstaller' installed but the command isn't runnable.
    echo Try closing and reopening your terminal, then re-run this script
    echo ^(the venv's Scripts folder may not be on PATH yet in this session^).
    exit /b 1
)

echo.
echo Running the test suite before packaging (a broken build should never ship)...
python -m unittest discover -s tests
if %errorlevel% neq 0 (
    echo ERROR: Tests failed — aborting build. Fix the failing test(s) above
    echo before packaging; do not skip this check.
    exit /b 1
)

echo.
echo Building the .exe with PyInstaller (single-file build)...
echo (add --log-level DEBUG to this command yourself for full diagnostic
echo  output if this step fails and the message below isn't enough)
pyinstaller packaging\blueline.spec --noconfirm
if %errorlevel% neq 0 (
    echo.
    echo ERROR: PyInstaller exited with an error — see the traceback above.
    echo This is the actual failure; nothing below this point ran. Common
    echo causes: a hidden import PyInstaller couldn't find ^(add it to the
    echo hiddenimports list in packaging\blueline.spec^), or an API
    echo mismatch between this PyInstaller version and the spec file's
    echo assumptions ^(re-run with --log-level DEBUG and read the traceback
    echo for the exact line and error^).
    exit /b 1
)

if not exist "dist\BlueLine.exe" (
    echo.
    echo ERROR: PyInstaller reported success but dist\BlueLine.exe does not
    echo exist. Check the output above for warnings — this shouldn't happen
    echo silently, so please report the full console output if you hit this.
    exit /b 1
)

echo.
echo === Build complete ===
echo Your application is the single file: dist\BlueLine.exe
for %%F in (dist\BlueLine.exe) do echo Size: %%~zF bytes
echo That one file is fully standalone — copy it anywhere and run it directly.
echo Scan history is stored in your user data folder (%LOCALAPPDATA%\BlueLine),
echo never next to the exe, so the exe itself never needs write access to its own folder.
echo.
echo Sanity check: run "dist\BlueLine.exe" now and confirm a browser window
echo (or a native window, if pywebview installed correctly) opens showing
echo the BlueLine UI before you consider this build done.
