#!/bin/bash

# Remove nist_security_baseline script
rm -f "${MUNKIPATH}preflight.d/nist_security_baseline.sh"

# Remove nist_security_baseline.txt file
rm -f "${MUNKIPATH}preflight.d/cache/nist_security_baseline.plist"
