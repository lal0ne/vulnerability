@echo off
setlocal enabledelayedexpansion

set "blocked_extensions=.htm .html .shtml .phtml .jse .jar .xml .css .asp .aspx .jsp .sql .hta .dll .bat .com .sh .bash .py .pl.js .php .svg .swf .dfxp .exe"

echo Checking for potential compromise...
set "compromised=0"

for /r %%i in (*) do (
    set "filename=%%~nxi"
    if "!filename!" neq "checker.bat" (
        for %%x in (%blocked_extensions%) do (
            if "%%~xi"=="%%x" (
                echo Potential compromised file found: "%%i"
                set "compromised=1"
            )
        )
    )
)

if !compromised! == 1 (
    echo If you did not place these files yourself, your system might have been compromised
    echo Please perform a security check and consider seeking assistance
) else (
    echo Looks good to me
)

pause
