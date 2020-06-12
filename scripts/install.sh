#!/bin/bash

# nist_security_baseline controller
CTL="${BASEURL}index.php?/module/nist_security_baseline/"

# Get the scripts in the proper directories
"${CURL[@]}" "${CTL}get_script/nist_security_baseline.sh" -o "${MUNKIPATH}preflight.d/nist_security_baseline.sh"

# Check exit status of curl
if [ $? = 0 ]; then
	# Make executable
	chmod a+x "${MUNKIPATH}preflight.d/nist_security_baseline.sh"

	# Set preference to include this file in the preflight check
	setreportpref "nist_security_baseline" "${CACHEPATH}nist_security_baseline.txt"

else
	echo "Failed to download all required components!"
	rm -f "${MUNKIPATH}preflight.d/nist_security_baseline.sh"

	# Signal that we had an error
	ERR=1
fi
