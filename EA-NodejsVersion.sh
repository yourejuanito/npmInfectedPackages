#!/bin/bash

if [ -f "/usr/local/bin/node" ] || [ -f "/opt/homebrew/bin/node" ]
then
    echo "<result>`node -v`</result>"
else
    echo "<result>Node.js is not installed</result>"
fi