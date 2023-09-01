#!/bin/bash

blocked_extensions=".htm .html .shtml .phtml .jse .jar .xml .css .asp .aspx .jsp .sql .hta .dll .bat .com .sh .bash .py .pl.js .php .svg .swf .dfxp .exe"

echo "Checking for potential compromise..."
compromised=0

for file in $(find . -type f); do
    filename=$(basename "$file")
    extension="${filename##*.}"
    if [[ "$filename" != "checker.sh" ]]; then
        if [[ $blocked_extensions == *"$extension"* ]]; then
            echo "Potential compromised file found: $file"
            compromised=1
        fi
    fi
done

if [ $compromised -eq 0 ]; then
    echo "Looks good to me ¯\_(ツ)_/¯"
else
        echo "If you did not place these files yourself, your system might have been compromised"
        echo "Please perform a security check and consider seeking assistance"
fi
