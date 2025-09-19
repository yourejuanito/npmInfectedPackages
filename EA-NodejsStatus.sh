#!/bin/zsh
REPORT="/Library/Application Support/Security/intel/npm_findings.csv"

if [ ! -f "$REPORT" ]; then
  echo "<result>No report</result>"
  exit 0
fi

lines=$(wc -l < "$REPORT")

if [ "$lines" -le 1 ]; then
  echo "<result>CLEAR</result>"
  exit 0
fi

# Skip header and return package_name + version(s)
IMPACTED=$(tail -n +2 "$REPORT" | awk -F',' '{print $1 "@" $2 " (" $4 ")"}' | paste -sd "; " -)

echo "<result>$IMPACTED</result>"