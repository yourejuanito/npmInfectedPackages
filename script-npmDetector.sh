#!/bin/zsh
set -euo pipefail

CSV="/Library/Application Support/Security/intel/malware_report.csv"
DETECTOR="/Library/Application Support/Security/intel/npm_detector.py"

# Expand PATH so Jamf can see Homebrew/npm when present
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Helpful debug
echo "Using PATH=$PATH"
echo "Detector exists? $( [ -e "$DETECTOR" ] && echo yes || echo no )"
echo "CSV exists? $( [ -e "$CSV" ] && echo yes || echo no )"
echo "npm path: $(command -v npm || echo 'not found')"
echo "node path: $(command -v node || echo 'not found')"

# Only require the detector file; let the detector decide what to do re: npm
if [ ! -e "$DETECTOR" ]; then
  echo "Detector missing at $DETECTOR"
  exit 1
fi

# Run the detector (it already exits cleanly if npm isn't present)
# Add local roots if you want project scans
/usr/bin/python3 "$DETECTOR" --csv "$CSV" --roots "/Users" "/opt" || true