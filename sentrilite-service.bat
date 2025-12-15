@echo off
REM Sentrilite Windows Service Runner - Simple Version
REM Usage: sentrilite-service-simple.bat [start|stop|restart|status]

setlocal enabledelayedexpansion

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "BINARY_NAME=sentrilite.exe"
set "BINARY_PATH=%SCRIPT_DIR%%BINARY_NAME%"
set "PID_FILE=%SCRIPT_DIR%sentrilite.pid"
set "LOG_FILE=%SCRIPT_DIR%sentrilite.log"

echo ========================================
echo Sentrilite Service Manager
echo ========================================
echo.

REM Check if binary exists
if not exist "%BINARY_PATH%" (
    echo ERROR: %BINARY_NAME% not found at:
    echo %BINARY_PATH%
    echo.
    pause
    exit /b 1
)

echo Binary found: %BINARY_PATH%
echo.

REM Handle commands
if "%1"=="" goto :usage
if /I "%1"=="start" goto :start
if /I "%1"=="stop" goto :stop
if /I "%1"=="restart" goto :restart
if /I "%1"=="status" goto :status
goto :usage

:start
echo Starting Sentrilite...
echo.

REM Check if already running by process name
tasklist /FI "IMAGENAME eq %BINARY_NAME%" 2>NUL | find /I "%BINARY_NAME%">NUL
if %ERRORLEVEL%==0 (
    echo Sentrilite is already running!
    echo.
    tasklist /FI "IMAGENAME eq %BINARY_NAME%" /FO TABLE
    echo.
    pause
    exit /b 1
)

REM Start the process using PowerShell
echo Starting process in background...
powershell -Command "$p = Start-Process -FilePath '%BINARY_PATH%' -RedirectStandardOutput '%LOG_FILE%' -RedirectStandardError '%SCRIPT_DIR%sentrilite-error.log' -WindowStyle Hidden -PassThru; Start-Sleep -Milliseconds 1000; if (-not $p.HasExited) { Write-Host 'Started with PID:' $p.Id; Start-Sleep -Milliseconds 1000; if (Test-Path '%SCRIPT_DIR%sentrilite-error.log') { try { $errorContent = Get-Content '%SCRIPT_DIR%sentrilite-error.log' -ErrorAction SilentlyContinue -Raw; if ($errorContent) { Start-Sleep -Milliseconds 500; $errorContent | Out-File -FilePath '%LOG_FILE%' -Append -ErrorAction SilentlyContinue } } catch {}; Remove-Item '%SCRIPT_DIR%sentrilite-error.log' -ErrorAction SilentlyContinue }; exit 0 } else { Write-Host 'ERROR: Process exited immediately with code:' $p.ExitCode; exit 1 }"
REM Don't check PowerShell exit code - verify by process name instead

REM Verify it's running by process name (wait a bit longer for process to fully start)
timeout /t 3 /nobreak >NUL
REM Check multiple times to give process time to start
set /a CHECK_COUNT=0
:check_loop
tasklist /FI "IMAGENAME eq %BINARY_NAME%" 2>NUL | find /I "%BINARY_NAME%">NUL
if %ERRORLEVEL%==0 goto :started
set /a CHECK_COUNT+=1
if !CHECK_COUNT! geq 5 goto :not_started
timeout /t 1 /nobreak >NUL
goto :check_loop

:started
echo.
echo Sentrilite started successfully!
echo.
tasklist /FI "IMAGENAME eq %BINARY_NAME%" /FO TABLE
echo.
echo Log file: %LOG_FILE%
echo To view logs: type %LOG_FILE%
echo Or: powershell -Command "Get-Content '%LOG_FILE%' -Tail 20 -Wait"
echo.
exit /b 0

:not_started
    echo.
    echo ERROR: Process started but is not running
    echo The process may have exited immediately after starting.
    echo.
    echo Checking log files for errors...
    if exist "%LOG_FILE%" (
        echo.
        echo Contents of %LOG_FILE%:
        echo ----------------------------------------
        type "%LOG_FILE%"
        echo ----------------------------------------
    )
    if exist "%SCRIPT_DIR%sentrilite-error.log" (
        echo.
        echo Contents of error log:
        echo ----------------------------------------
        type "%SCRIPT_DIR%sentrilite-error.log"
        echo ----------------------------------------
    )
    echo.
    echo Common issues:
    echo   - Missing license file
    echo   - Missing sys.conf configuration file
    echo   - Invalid configuration
    echo.
    pause
    exit /b 1
)

:stop
echo Stopping Sentrilite...
echo.

REM Always try to stop by process name - taskkill will fail gracefully if not running
echo Attempting to stop all %BINARY_NAME% processes...
taskkill /IM %BINARY_NAME% /F >NUL 2>&1
set KILL_RESULT=%ERRORLEVEL%
timeout /t 2 /nobreak >NUL

REM Check if any processes are still running
tasklist /FI "IMAGENAME eq %BINARY_NAME%" 2>NUL | find /I "%BINARY_NAME%">"%TEMP%\sentrilite_still_running.tmp"
if exist "%TEMP%\sentrilite_still_running.tmp" (
    for %%A in ("%TEMP%\sentrilite_still_running.tmp") do set FILE_SIZE=%%~zA
    if !FILE_SIZE! gtr 0 (
        echo WARNING: Some %BINARY_NAME% processes may still be running:
        tasklist /FI "IMAGENAME eq %BINARY_NAME%" /FO TABLE
        echo.
        echo Try running as Administrator or manually: taskkill /IM %BINARY_NAME% /F
    ) else (
        if %KILL_RESULT%==0 (
            echo Sentrilite stopped successfully
        ) else (
            echo No %BINARY_NAME% processes were running
        )
    )
    del "%TEMP%\sentrilite_still_running.tmp" 2>NUL
) else (
    if %KILL_RESULT%==0 (
        echo Sentrilite stopped successfully
    ) else (
        echo No %BINARY_NAME% processes were running
    )
)

REM Also try to stop by PID if PID file exists
if exist "%PID_FILE%" (
    set /p PID_FROM_FILE=<"%PID_FILE%"
    set "PID_FROM_FILE=!PID_FROM_FILE: =!"
    if not "!PID_FROM_FILE!"=="" (
        echo.
        echo Attempting to stop PID: !PID_FROM_FILE!
        taskkill /PID !PID_FROM_FILE! /F >NUL 2>&1
        timeout /t 1 /nobreak >NUL
    )
    echo Removing PID file...
    del "%PID_FILE%" 2>NUL
)

echo.
pause
exit /b 0

:restart
echo Restarting Sentrilite...
echo.
call :stop
timeout /t 2 /nobreak >NUL
call :start
exit /b %ERRORLEVEL%

:status
echo Checking Sentrilite status...
echo.

REM Check by process name
tasklist /FI "IMAGENAME eq %BINARY_NAME%" 2>NUL | find /I "%BINARY_NAME%">NUL
if %ERRORLEVEL%==0 (
    echo Sentrilite is RUNNING
    echo.
    echo Process list:
    tasklist /FI "IMAGENAME eq %BINARY_NAME%" /FO TABLE
    echo.
    echo Log file: %LOG_FILE%
    if exist "%LOG_FILE%" (
        echo.
        echo Last 10 lines of log:
        echo ----------------------------------------
        powershell -Command "Get-Content '%LOG_FILE%' -Tail 10"
        echo ----------------------------------------
    )
    echo.
    exit /b 0
) else (
    echo Sentrilite is NOT running
    if exist "%PID_FILE%" (
        echo Removing stale PID file...
        del "%PID_FILE%" 2>NUL
    )
    echo.
    pause
    exit /b 1
)

:usage
echo Usage: %~nx0 {start^|stop^|restart^|status}
echo.
echo Commands:
echo   start    - Start Sentrilite as a background daemon
echo   stop     - Stop the running Sentrilite daemon
echo   restart  - Restart the Sentrilite daemon
echo   status   - Show the current status
echo.
echo Examples:
echo   %~nx0 start
echo   %~nx0 stop
echo   %~nx0 status
echo.
pause
exit /b 1

