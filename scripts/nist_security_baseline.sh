#!/bin/sh

# Script to collect data
# and put the data into outputfile

CWD=$(dirname $0)
CACHEDIR="$CWD/cache/"
OUTPUT_FILE="${CACHEDIR}nist_security_baseline.txt"
SEPARATOR=' = '

# Business logic goes here
# Replace 'echo' in the following lines with the data collection commands for your module.
echo 'Running the command to check the settings for: audit_acls_files_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -le $(/usr/bin/awk -F: '/^dir/{print $2}' /etc/security/audit_control) | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":")
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_files_configure passed..."
    AUDIT_ACLS_FILES_CONFIGURE=1
else
    echo "audit_acls_files_configure FAILED..."
    AUDIT_ACLS_FILES_CONFIGURE=0
fi

echo 'Running the command to check the settings for: audit_acls_files_mode_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | tr -d ' ')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_files_mode_configure passed..."
    AUDIT_ACLS_FILES_MODE_CONFIGURE=1
else
    echo "audit_acls_files_mode_configure FAILED..."
    AUDIT_ACLS_FILES_MODE_CONFIGURE=0
fi

echo 'Running the command to check the settings for: audit_acls_folder_wheel_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_folder_wheel_configure passed..."
    AUDIT_ACLS_FOLDER_WHEEL_CONFIGURE=1
else
    echo "audit_acls_folder_wheel_configure FAILED..."
    AUDIT_ACLS_FOLDER_WHEEL_CONFIGURE=0
fi

echo 'Running the command to check the settings for: audit_acls_folders_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":")
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_folders_configure passed..."
    AUDIT_ACLS_FOLDERS_CONFIGURE=1
else
    echo "audit_acls_folders_configure FAILED..."
    AUDIT_ACLS_FOLDERS_CONFIGURE=0
fi

echo 'Running the command to check the settings for: audit_acls_folders_mode_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}'))
# expected result {'integer': 700}

if [[ $result_value == "700" ]]; then
    echo "audit_acls_folders_mode_configure passed..."
    AUDIT_ACLS_FOLDERS_MODE_CONFIGURE=1
else
    echo "audit_acls_folders_mode_configure FAILED..."
    AUDIT_ACLS_FOLDERS_MODE_CONFIGURE=0
fi


# Output data here
echo "audit_acls_files_configure${SEPARATOR}${AUDIT_ACLS_FILES_CONFIGURE}" > ${OUTPUT_FILE}
echo "audit_acls_files_mode_configure${SEPARATOR}${AUDIT_ACLS_FILES_MODE_CONFIGURE}" >> ${OUTPUT_FILE}
echo "audit_acls_folder_wheel_configure${SEPARATOR}${AUDIT_ACLS_FOLDER_WHEEL_CONFIGURE}" >> ${OUTPUT_FILE}
echo "audit_acls_folders_configure${SEPARATOR}${AUDIT_ACLS_FOLDERS_CONFIGURE}" >> ${OUTPUT_FILE}
echo "audit_acls_folders_mode_configure${SEPARATOR}${AUDIT_ACLS_FOLDERS_MODE_CONFIGURE}" >> ${OUTPUT_FILE}
