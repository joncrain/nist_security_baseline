#!/bin/zsh

##  This script will attempt to audit all of the settings based on the installed profile.

##  This script is provided as-is and should be fully tested on a system that is not in a production environment.  

###################  COMMANDS START BELOW THIS LINE  ###################

## Must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# get the currently logged in user
CURRENT_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }')

# configure colors for text
RED='\e[31m'
STD='[0;0;39m'
GREEN='\e[32m'
YELLOW='\e[33m'

# setup files
audit_plist="/usr/local/munkireport/scripts/cache/nist_baseline.plist"
audit_log="/Library/Logs/allrules_baseline.log"

run_scan(){
# append to existing logfile
echo "$(date -u) Beginning high baseline scan" >> "$audit_log"

# write timestamp of last compliance check
defaults write "$audit_plist" lastComplianceCheck "$(date)"

#####----- Rule: audit_acls_files_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
## SI-11(b)
echo 'Running the command to check the settings for: audit_acls_files_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -le $(/usr/bin/awk -F: '/^dir/{print $2}' /etc/security/audit_control) | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":")
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_files_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_files_configure -bool NO
else
    echo "audit_acls_files_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_files_configure -bool YES
fi

#####----- Rule: audit_acls_files_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
echo 'Running the command to check the settings for: audit_acls_files_mode_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | tr -d ' ')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_files_mode_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_files_mode_configure -bool NO
else
    echo "audit_acls_files_mode_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_files_mode_configure -bool YES
fi

#####----- Rule: audit_acls_folder_wheel_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
echo 'Running the command to check the settings for: audit_acls_folder_wheel_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_folder_wheel_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_folder_wheel_configure -bool NO
else
    echo "audit_acls_folder_wheel_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_folder_wheel_configure -bool YES
fi

#####----- Rule: audit_acls_folders_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
## SI-11(b)
echo 'Running the command to check the settings for: audit_acls_folders_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":")
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_acls_folders_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_folders_configure -bool NO
else
    echo "audit_acls_folders_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_folders_configure -bool YES
fi

#####----- Rule: audit_acls_folders_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
echo 'Running the command to check the settings for: audit_acls_folders_mode_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}'))
# expected result {'integer': 700}

if [[ $result_value == "700" ]]; then
    echo "audit_acls_folders_mode_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_folders_mode_configure -bool NO
else
    echo "audit_acls_folders_mode_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_acls_folders_mode_configure -bool YES
fi

#####----- Rule: audit_configure_capacity_notify -----#####
## Addresses the following NIST 800-53 controls: 
## AU-5(1)
echo 'Running the command to check the settings for: audit_configure_capacity_notify ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "^minfree:25" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_configure_capacity_notify passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_configure_capacity_notify -bool NO
else
    echo "audit_configure_capacity_notify FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_configure_capacity_notify -bool YES
fi

#####----- Rule: audit_failure_halt -----#####
## Addresses the following NIST 800-53 controls: 
## AU-5(b)
echo 'Running the command to check the settings for: audit_failure_halt ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^policy.*ahlt" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_failure_halt passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_failure_halt -bool NO
else
    echo "audit_failure_halt FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_failure_halt -bool YES
fi

#####----- Rule: audit_files_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
echo 'Running the command to check the settings for: audit_files_group_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_files_group_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_files_group_configure -bool NO
else
    echo "audit_files_group_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_files_group_configure -bool YES
fi

#####----- Rule: audit_files_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
echo 'Running the command to check the settings for: audit_files_owner_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_files_owner_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_files_owner_configure -bool NO
else
    echo "audit_files_owner_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_files_owner_configure -bool YES
fi

#####----- Rule: audit_flags_aa_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-12(c)
echo 'Running the command to check the settings for: audit_flags_aa_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^flags.*aa" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_flags_aa_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_aa_configure -bool NO
else
    echo "audit_flags_aa_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_aa_configure -bool YES
fi

#####----- Rule: audit_flags_ad_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AC-2(4)
## AC-6(9)
## AU-12(c)
## MA-4(1)(a)
echo 'Running the command to check the settings for: audit_flags_ad_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^flags.*ad" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_flags_ad_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_ad_configure -bool NO
else
    echo "audit_flags_ad_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_ad_configure -bool YES
fi

#####----- Rule: audit_flags_failed_file_read_restriction_enforced -----#####
## Addresses the following NIST 800-53 controls: 
## AU-12(c)
## AU-9
## CM-5(1)
echo 'Running the command to check the settings for: audit_flags_failed_file_read_restriction_enforced ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^flags.*-fr" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_flags_failed_file_read_restriction_enforced passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_failed_file_read_restriction_enforced -bool NO
else
    echo "audit_flags_failed_file_read_restriction_enforced FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_failed_file_read_restriction_enforced -bool YES
fi

#####----- Rule: audit_flags_failed_file_write_access_restriction_enforced -----#####
## Addresses the following NIST 800-53 controls: 
## AU-12(c)
## AU-9
## CM-5(1)
echo 'Running the command to check the settings for: audit_flags_failed_file_write_access_restriction_enforced ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^flags.*-fw" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_flags_failed_file_write_access_restriction_enforced passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_failed_file_write_access_restriction_enforced -bool NO
else
    echo "audit_flags_failed_file_write_access_restriction_enforced FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_failed_file_write_access_restriction_enforced -bool YES
fi

#####----- Rule: audit_flags_file_attr_mod_access_restriction_enforced -----#####
## Addresses the following NIST 800-53 controls: 
## AU-12(c)
## AU-9
## CM-5(1)
echo 'Running the command to check the settings for: audit_flags_file_attr_mod_access_restriction_enforced ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^flags.*fm" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_flags_file_attr_mod_access_restriction_enforced passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_file_attr_mod_access_restriction_enforced -bool NO
else
    echo "audit_flags_file_attr_mod_access_restriction_enforced FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_file_attr_mod_access_restriction_enforced -bool YES
fi

#####----- Rule: audit_flags_lo_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AC-17(1)
## AU-12(c)
echo 'Running the command to check the settings for: audit_flags_lo_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^flags*.lo" /etc/security/audit_control)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_flags_lo_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_lo_configure -bool NO
else
    echo "audit_flags_lo_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_flags_lo_configure -bool YES
fi

#####----- Rule: audit_folder_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
echo 'Running the command to check the settings for: audit_folder_group_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | awk '{print $4}')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_folder_group_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_folder_group_configure -bool NO
else
    echo "audit_folder_group_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_folder_group_configure -bool YES
fi

#####----- Rule: audit_folder_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-9
echo 'Running the command to check the settings for: audit_folder_owner_configure ...' | tee -a "$audit_log"
result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | awk '{print $3}')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "audit_folder_owner_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_folder_owner_configure -bool NO
else
    echo "audit_folder_owner_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_folder_owner_configure -bool YES
fi

#####----- Rule: audit_retention_one_week_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-4
echo 'Running the command to check the settings for: audit_retention_one_week_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control)
# expected result {'string': '7d'}

if [[ $result_value == "7d" ]]; then
    echo "audit_retention_one_week_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_retention_one_week_configure -bool NO
else
    echo "audit_retention_one_week_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_retention_one_week_configure -bool YES
fi

#####----- Rule: audit_settings_failure_notify -----#####
## Addresses the following NIST 800-53 controls: 
## AU-5(2)
echo 'Running the command to check the settings for: audit_settings_failure_notify ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "logger -s -p" /etc/security/audit_warn)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_settings_failure_notify passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_settings_failure_notify -bool NO
else
    echo "audit_settings_failure_notify FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_settings_failure_notify -bool YES
fi

#####----- Rule: auth_pam_login_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
## IA-2(3)
echo 'Running the command to check the settings for: auth_pam_login_smartcard_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login)
# expected result {'integer': 2}

if [[ $result_value == "2" ]]; then
    echo "auth_pam_login_smartcard_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_login_smartcard_enforce -bool NO
else
    echo "auth_pam_login_smartcard_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_login_smartcard_enforce -bool YES
fi

#####----- Rule: auth_pam_su_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
## IA-2(3)
echo 'Running the command to check the settings for: auth_pam_su_smartcard_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su)
# expected result {'integer': 2}

if [[ $result_value == "2" ]]; then
    echo "auth_pam_su_smartcard_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_su_smartcard_enforce -bool NO
else
    echo "auth_pam_su_smartcard_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_su_smartcard_enforce -bool YES
fi

#####----- Rule: auth_pam_sudo_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
## IA-2(3)
echo 'Running the command to check the settings for: auth_pam_sudo_smartcard_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo)
# expected result {'integer': 2}

if [[ $result_value == "2" ]]; then
    echo "auth_pam_sudo_smartcard_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -bool NO
else
    echo "auth_pam_sudo_smartcard_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -bool YES
fi

#####----- Rule: auth_smartcard_allow -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2(12)
echo 'Running the command to check the settings for: auth_smartcard_allow ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowSmartCard = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "auth_smartcard_allow passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_allow -bool NO
else
    echo "auth_smartcard_allow FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_allow -bool YES
fi

#####----- Rule: auth_smartcard_certificate_trust_enforce_moderate -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2(12)
## IA-5(2), IA-5(2)(d)
echo 'Running the command to check the settings for: auth_smartcard_certificate_trust_enforce_moderate ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk '/checkCertificateTrust/{print substr($3, 1, length($3)-1)}')
# expected result {'integer': 2}

if [[ $result_value == "2" ]]; then
    echo "auth_smartcard_certificate_trust_enforce_moderate passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -bool NO
else
    echo "auth_smartcard_certificate_trust_enforce_moderate FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -bool YES
fi

#####----- Rule: auth_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2, IA-2(1), IA-2(11), IA-2(2), IA-2(3), IA-2(4), IA-2(6)
## IA-5(2)(b), IA-5(2)(c)
## MA-4(c)
echo 'Running the command to check the settings for: auth_smartcard_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'enforceSmartCard = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "auth_smartcard_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_enforce -bool NO
else
    echo "auth_smartcard_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_smartcard_enforce -bool YES
fi

#####----- Rule: auth_ssh_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2, IA-2(1), IA-2(11), IA-2(2), IA-2(3), IA-2(4), IA-2(6)
## IA-5(2)(b), IA-5(2)(c)
## MA-4(c)
echo 'Running the command to check the settings for: auth_ssh_smartcard_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec '^(PasswordAuthentication\s+no|ChallengeResponseAuthentication\s+no)' /etc/ssh/sshd_config)
# expected result {'integer': 2}

if [[ $result_value == "2" ]]; then
    echo "auth_ssh_smartcard_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_ssh_smartcard_enforce -bool NO
else
    echo "auth_ssh_smartcard_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" auth_ssh_smartcard_enforce -bool YES
fi

#####----- Rule: sysprefs_ad_tracking_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(b)
echo 'Running the command to check the settings for: sysprefs_ad_tracking_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"forceLimitAdTracking" = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_ad_tracking_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_ad_tracking_disable -bool NO
else
    echo "sysprefs_ad_tracking_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_ad_tracking_disable -bool YES
fi

#####----- Rule: sysprefs_afp_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: sysprefs_afp_disable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AppleFileServer" => true')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_afp_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_afp_disable -bool NO
else
    echo "sysprefs_afp_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_afp_disable -bool YES
fi

#####----- Rule: sysprefs_apple_watch_unlock_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(b)
echo 'Running the command to check the settings for: sysprefs_apple_watch_unlock_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowAutoUnlock = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_apple_watch_unlock_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_apple_watch_unlock_disable -bool NO
else
    echo "sysprefs_apple_watch_unlock_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_apple_watch_unlock_disable -bool YES
fi

#####----- Rule: sysprefs_automatic_login_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: sysprefs_automatic_login_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"com.apple.login.mcx.DisableAutoLoginClient" = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_automatic_login_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_automatic_login_disable -bool NO
else
    echo "sysprefs_automatic_login_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_automatic_login_disable -bool YES
fi

#####----- Rule: sysprefs_bluetooth_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-18(3)
## SC-8
echo 'Running the command to check the settings for: sysprefs_bluetooth_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableBluetooth = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_bluetooth_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_bluetooth_disable -bool NO
else
    echo "sysprefs_bluetooth_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_bluetooth_disable -bool YES
fi

#####----- Rule: sysprefs_bluetooth_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-18, AC-18(4)
## CM-6(b)
## CM-7(1)
echo 'Running the command to check the settings for: sysprefs_bluetooth_sharing_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled)
# expected result {'boolean': 0}

if [[ $result_value == "0" ]]; then
    echo "sysprefs_bluetooth_sharing_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -bool NO
else
    echo "sysprefs_bluetooth_sharing_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -bool YES
fi

#####----- Rule: sysprefs_content_caching_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(b)
echo 'Running the command to check the settings for: sysprefs_content_caching_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowContentCaching = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_content_caching_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_content_caching_disable -bool NO
else
    echo "sysprefs_content_caching_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_content_caching_disable -bool YES
fi

#####----- Rule: sysprefs_diagnostics_reports_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(b)
## SC-7(10)
## SI-4
echo 'Running the command to check the settings for: sysprefs_diagnostics_reports_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(allowDiagnosticSubmission = 0|AutoSubmit = 0)')
# expected result {'integer': 2}

if [[ $result_value == "2" ]]; then
    echo "sysprefs_diagnostics_reports_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -bool NO
else
    echo "sysprefs_diagnostics_reports_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -bool YES
fi

#####----- Rule: sysprefs_filevault_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## SC-28, SC-28(1)
echo 'Running the command to check the settings for: sysprefs_filevault_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On.")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_filevault_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_filevault_enforce -bool NO
else
    echo "sysprefs_filevault_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_filevault_enforce -bool YES
fi

#####----- Rule: sysprefs_find_my_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(b)
## CM-8(8)
echo 'Running the command to check the settings for: sysprefs_find_my_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(allowCloudFMM = 0|allowFindMyDevice = 0|allowFindMyFriends = 0|DisableFMMiCloudSetting = 1)')
# expected result {'integer': 4}

if [[ $result_value == "4" ]]; then
    echo "sysprefs_find_my_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_find_my_disable -bool NO
else
    echo "sysprefs_find_my_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_find_my_disable -bool YES
fi

#####----- Rule: sysprefs_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-19
## AC-4
## AC-6(1)
## CM-6(b)
## CM-7
## SC-7(12)
echo 'Running the command to check the settings for: sysprefs_firewall_enable ...' | tee -a "$audit_log"
result_value=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -c "Firewall is enabled")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_firewall_enable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_firewall_enable -bool NO
else
    echo "sysprefs_firewall_enable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_firewall_enable -bool YES
fi

#####----- Rule: sysprefs_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
## SC-7(16)
echo 'Running the command to check the settings for: sysprefs_firewall_stealth_mode_enable ...' | tee -a "$audit_log"
result_value=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | /usr/bin/grep -c "Stealth mode enabled")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_firewall_stealth_mode_enable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -bool NO
else
    echo "sysprefs_firewall_stealth_mode_enable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -bool YES
fi

#####----- Rule: sysprefs_gatekeeper_identified_developers_allowed -----#####
## Addresses the following NIST 800-53 controls: 
## CM-5(3)
## CM-6(b)
## SI-7(15)
echo 'Running the command to check the settings for: sysprefs_gatekeeper_identified_developers_allowed ...' | tee -a "$audit_log"
result_value=$(/usr/sbin/spctl --status --verbose | /usr/bin/grep -c "developer id enabled")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_gatekeeper_identified_developers_allowed passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_gatekeeper_identified_developers_allowed -bool NO
else
    echo "sysprefs_gatekeeper_identified_developers_allowed FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_gatekeeper_identified_developers_allowed -bool YES
fi

#####----- Rule: sysprefs_gatekeeper_override_disallow -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
## SI-7(15)
echo 'Running the command to check the settings for: sysprefs_gatekeeper_override_disallow ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableOverride = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_gatekeeper_override_disallow passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_gatekeeper_override_disallow -bool NO
else
    echo "sysprefs_gatekeeper_override_disallow FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_gatekeeper_override_disallow -bool YES
fi

#####----- Rule: sysprefs_hot_corners_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(1)
echo 'Running the command to check the settings for: sysprefs_hot_corners_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '"wvous-bl-corner" = 0|"wvous-br-corner" = 0|"wvous-tl-corner" = 0|"wvous-tr-corner" = 0')
# expected result {'integer': 4}

if [[ $result_value == "4" ]]; then
    echo "sysprefs_hot_corners_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_hot_corners_disable -bool NO
else
    echo "sysprefs_hot_corners_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_hot_corners_disable -bool YES
fi

#####----- Rule: sysprefs_internet_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: sysprefs_internet_sharing_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'forceInternetSharingOff = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_internet_sharing_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_internet_sharing_disable -bool NO
else
    echo "sysprefs_internet_sharing_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_internet_sharing_disable -bool YES
fi

#####----- Rule: sysprefs_location_services_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: sysprefs_location_services_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled)
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "sysprefs_location_services_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_location_services_disable -bool NO
else
    echo "sysprefs_location_services_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_location_services_disable -bool YES
fi

#####----- Rule: sysprefs_loginwindow_prompt_username_password_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: sysprefs_loginwindow_prompt_username_password_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SHOWFULLNAME = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_loginwindow_prompt_username_password_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_loginwindow_prompt_username_password_enforce -bool NO
else
    echo "sysprefs_loginwindow_prompt_username_password_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_loginwindow_prompt_username_password_enforce -bool YES
fi

#####----- Rule: sysprefs_password_hints_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: sysprefs_password_hints_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'RetriesUntilHint = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_password_hints_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_password_hints_disable -bool NO
else
    echo "sysprefs_password_hints_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_password_hints_disable -bool YES
fi

#####----- Rule: sysprefs_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(b)
echo 'Running the command to check the settings for: sysprefs_rae_disable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => true')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_rae_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_rae_disable -bool NO
else
    echo "sysprefs_rae_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_rae_disable -bool YES
fi

#####----- Rule: sysprefs_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-17
## CM-6(b)
echo 'Running the command to check the settings for: sysprefs_screen_sharing_disable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => true')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_screen_sharing_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_screen_sharing_disable -bool NO
else
    echo "sysprefs_screen_sharing_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_screen_sharing_disable -bool YES
fi

#####----- Rule: sysprefs_siri_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(b)
echo 'Running the command to check the settings for: sysprefs_siri_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"Ironwood Allowed" = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_siri_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_siri_disable -bool NO
else
    echo "sysprefs_siri_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_siri_disable -bool YES
fi

#####----- Rule: sysprefs_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: sysprefs_smbd_disable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => true')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_smbd_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_smbd_disable -bool NO
else
    echo "sysprefs_smbd_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_smbd_disable -bool YES
fi

#####----- Rule: sysprefs_ssh_enable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-17(2), AC-17(4)
## IA-2(8), IA-2(9)
## MA-4(6)
## SC-8, SC-8(1), SC-8(2)
echo 'Running the command to check the settings for: sysprefs_ssh_enable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => false')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_ssh_enable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_ssh_enable -bool NO
else
    echo "sysprefs_ssh_enable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_ssh_enable -bool YES
fi

#####----- Rule: sysprefs_time_server_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AU-8(1)(a), AU-8(1)(b)
echo 'Running the command to check the settings for: sysprefs_time_server_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk -F "= " '/timeServer/{print $2}' | /usr/bin/tr -d ';')
# expected result {'string': 'time-a.nist.gov,time-b.nist.gov'}

if [[ $result_value == "time-a.nist.gov,time-b.nist.gov" ]]; then
    echo "sysprefs_time_server_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_time_server_configure -bool NO
else
    echo "sysprefs_time_server_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_time_server_configure -bool YES
fi

#####----- Rule: sysprefs_time_server_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AU-8(1)(a), AU-8(1)(b)
echo 'Running the command to check the settings for: sysprefs_time_server_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'TMAutomaticTimeOnlyEnabled = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_time_server_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_time_server_enforce -bool NO
else
    echo "sysprefs_time_server_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_time_server_enforce -bool YES
fi

#####----- Rule: sysprefs_token_removal_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(a)
echo 'Running the command to check the settings for: sysprefs_token_removal_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'tokenRemovalAction = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_token_removal_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_token_removal_enforce -bool NO
else
    echo "sysprefs_token_removal_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_token_removal_enforce -bool YES
fi

#####----- Rule: sysprefs_touchid_unlock_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(b)
echo 'Running the command to check the settings for: sysprefs_touchid_unlock_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowFingerprintForUnlock = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "sysprefs_touchid_unlock_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_touchid_unlock_disable -bool NO
else
    echo "sysprefs_touchid_unlock_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" sysprefs_touchid_unlock_disable -bool YES
fi

#####----- Rule: icloud_addressbook_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_addressbook_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudAddressBook = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_addressbook_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_addressbook_disable -bool NO
else
    echo "icloud_addressbook_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_addressbook_disable -bool YES
fi

#####----- Rule: icloud_calendar_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_calendar_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudCalendar = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_calendar_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_calendar_disable -bool NO
else
    echo "icloud_calendar_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_calendar_disable -bool YES
fi

#####----- Rule: icloud_mail_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_mail_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudMail = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_mail_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_mail_disable -bool NO
else
    echo "icloud_mail_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_mail_disable -bool YES
fi

#####----- Rule: icloud_notes_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_notes_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudNotes = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_notes_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_notes_disable -bool NO
else
    echo "icloud_notes_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_notes_disable -bool YES
fi

#####----- Rule: icloud_reminders_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_reminders_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudReminders = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_reminders_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_reminders_disable -bool NO
else
    echo "icloud_reminders_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_reminders_disable -bool YES
fi

#####----- Rule: icloud_appleid_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_appleid_prefpane_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'com.apple.preferences.AppleID')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_appleid_prefpane_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_appleid_prefpane_disable -bool NO
else
    echo "icloud_appleid_prefpane_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_appleid_prefpane_disable -bool YES
fi

#####----- Rule: icloud_bookmarks_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_bookmarks_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudBookmarks = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_bookmarks_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_bookmarks_disable -bool NO
else
    echo "icloud_bookmarks_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_bookmarks_disable -bool YES
fi

#####----- Rule: icloud_drive_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_drive_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudDocumentSync = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_drive_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_drive_disable -bool NO
else
    echo "icloud_drive_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_drive_disable -bool YES
fi

#####----- Rule: icloud_keychain_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_keychain_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudKeychainSync = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_keychain_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_keychain_disable -bool NO
else
    echo "icloud_keychain_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_keychain_disable -bool YES
fi

#####----- Rule: icloud_photos_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_photos_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudPhotoLibrary = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_photos_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_photos_disable -bool NO
else
    echo "icloud_photos_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_photos_disable -bool YES
fi

#####----- Rule: icloud_sync_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: icloud_sync_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "icloud_sync_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_sync_disable -bool NO
else
    echo "icloud_sync_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" icloud_sync_disable -bool YES
fi

#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
## AU-12, AU-12(3)
## AU-14(1)
## AU-3, AU-3(1)
## AU-8, AU-8(a), AU-8(b)
echo 'Running the command to check the settings for: audit_auditd_enabled ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "audit_auditd_enabled passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_auditd_enabled -bool NO
else
    echo "audit_auditd_enabled FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" audit_auditd_enabled -bool YES
fi

#####----- Rule: os_sip_enable -----#####
## Addresses the following NIST 800-53 controls: 
## AU-12, AU-12(a)
## AU-6(4)
## AU-7(1), AU-7(a), AU-7(b)
## AU-9, AU-9(3)
## CM-5(6)
## CM-6(b)
## SC-4
echo 'Running the command to check the settings for: os_sip_enable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/csrutil status | grep -c 'System Integrity Protection status: enabled.')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_sip_enable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_sip_enable -bool NO
else
    echo "os_sip_enable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_sip_enable -bool YES
fi

#####----- Rule: os_airdrop_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: os_airdrop_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableAirDrop = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_airdrop_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_airdrop_disable -bool NO
else
    echo "os_airdrop_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_airdrop_disable -bool YES
fi

#####----- Rule: os_appleid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
## CM-7(a)
echo 'Running the command to check the settings for: os_appleid_prompt_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipCloudSetup = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_appleid_prompt_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_appleid_prompt_disable -bool NO
else
    echo "os_appleid_prompt_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_appleid_prompt_disable -bool YES
fi

#####----- Rule: os_bonjour_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a), CM-7(b)
echo 'Running the command to check the settings for: os_bonjour_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'NoMulticastAdvertisements = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_bonjour_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_bonjour_disable -bool NO
else
    echo "os_bonjour_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_bonjour_disable -bool YES
fi

#####----- Rule: os_calendar_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_calendar_app_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/Calendar.app")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_calendar_app_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_calendar_app_disable -bool NO
else
    echo "os_calendar_app_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_calendar_app_disable -bool YES
fi

#####----- Rule: os_camera_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
## SC-15(3)
echo 'Running the command to check the settings for: os_camera_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCamera = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_camera_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_camera_disable -bool NO
else
    echo "os_camera_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_camera_disable -bool YES
fi

#####----- Rule: os_certificate_authority_trust -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(2)(a)
## SC-17
echo 'Running the command to check the settings for: os_certificate_authority_trust ...' | tee -a "$audit_log"
result_value=$(/usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/grep labl | awk -F'"' '{ print $4 }')
# expected result {'string': 'If this list does not contain approved root certificates, this is a finding.'}

if [[ $result_value == "If this list does not contain approved root certificates, this is a finding." ]]; then
    echo "os_certificate_authority_trust passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_certificate_authority_trust -bool NO
else
    echo "os_certificate_authority_trust FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_certificate_authority_trust -bool YES
fi

#####----- Rule: os_facetime_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_facetime_app_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/FaceTime.app")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_facetime_app_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_facetime_app_disable -bool NO
else
    echo "os_facetime_app_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_facetime_app_disable -bool YES
fi

#####----- Rule: os_filevault_autologin_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-3
echo 'Running the command to check the settings for: os_filevault_autologin_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableFDEAutoLogin = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_filevault_autologin_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_filevault_autologin_disable -bool NO
else
    echo "os_filevault_autologin_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_filevault_autologin_disable -bool YES
fi

#####----- Rule: os_firewall_default_deny_require -----#####
## Addresses the following NIST 800-53 controls: 
## CA-3(5)
## CM-6(b)
echo 'Running the command to check the settings for: os_firewall_default_deny_require ...' | tee -a "$audit_log"
result_value=$(/sbin/pfctl -a '*' -sr &> /dev/null | grep -c "block drop in all")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_firewall_default_deny_require passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_firewall_default_deny_require -bool NO
else
    echo "os_firewall_default_deny_require FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_firewall_default_deny_require -bool YES
fi

#####----- Rule: os_firewall_log_enable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: os_firewall_log_enable ...' | tee -a "$audit_log"
result_value=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | /usr/bin/grep -c "Log mode is on")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_firewall_log_enable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_firewall_log_enable -bool NO
else
    echo "os_firewall_log_enable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_firewall_log_enable -bool YES
fi

#####----- Rule: os_firmware_password_require -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: os_firmware_password_require ...' | tee -a "$audit_log"
result_value=$(/usr/sbin/firmwarepasswd -check | grep -c "Password Enabled: Yes")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_firmware_password_require passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_firmware_password_require -bool NO
else
    echo "os_firmware_password_require FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_firmware_password_require -bool YES
fi

#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-5(3)
## CM-6(b)
echo 'Running the command to check the settings for: os_gatekeeper_enable ...' | tee -a "$audit_log"
result_value=$(/usr/sbin/spctl --status | grep -c "assessments enabled")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_gatekeeper_enable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_gatekeeper_enable -bool NO
else
    echo "os_gatekeeper_enable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_gatekeeper_enable -bool YES
fi

#####----- Rule: os_guest_access_afp_disable -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2
echo 'Running the command to check the settings for: os_guest_access_afp_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'guestAccess = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_guest_access_afp_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_guest_access_afp_disable -bool NO
else
    echo "os_guest_access_afp_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_guest_access_afp_disable -bool YES
fi

#####----- Rule: os_guest_access_smb_disable -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2
echo 'Running the command to check the settings for: os_guest_access_smb_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'AllowGuestAccess = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_guest_access_smb_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_guest_access_smb_disable -bool NO
else
    echo "os_guest_access_smb_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_guest_access_smb_disable -bool YES
fi

#####----- Rule: os_guest_account_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-5(1)
echo 'Running the command to check the settings for: os_guest_account_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableGuestAccount = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_guest_account_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_guest_account_disable -bool NO
else
    echo "os_guest_account_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_guest_account_disable -bool YES
fi

#####----- Rule: os_handoff_disable -----#####
## Addresses the following NIST 800-53 controls: 
## AC-18(3)
## CM-6(b)
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_handoff_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowActivityContinuation = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_handoff_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_handoff_disable -bool NO
else
    echo "os_handoff_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_handoff_disable -bool YES
fi

#####----- Rule: os_home_folders_secure -----#####
## Addresses the following NIST 800-53 controls: 
## AC-6
## CM-6(b)
echo 'Running the command to check the settings for: os_home_folders_secure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d -perm -1 | grep -v "Shared" | grep -v "Guest" | wc -l | xargs)
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "os_home_folders_secure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_home_folders_secure -bool NO
else
    echo "os_home_folders_secure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_home_folders_secure -bool YES
fi

#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: os_httpd_disable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => true')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_httpd_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_httpd_disable -bool NO
else
    echo "os_httpd_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_httpd_disable -bool YES
fi

#####----- Rule: os_icloud_storage_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: os_icloud_storage_prompt_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipiCloudStorageSetup = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_icloud_storage_prompt_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_icloud_storage_prompt_disable -bool NO
else
    echo "os_icloud_storage_prompt_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_icloud_storage_prompt_disable -bool YES
fi

#####----- Rule: os_internet_accounts_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_internet_accounts_prefpane_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'com.apple.preferences.internetaccounts')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_internet_accounts_prefpane_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_internet_accounts_prefpane_disable -bool NO
else
    echo "os_internet_accounts_prefpane_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_internet_accounts_prefpane_disable -bool YES
fi

#####----- Rule: os_ir_support_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: os_ir_support_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DeviceEnabled = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_ir_support_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ir_support_disable -bool NO
else
    echo "os_ir_support_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ir_support_disable -bool YES
fi

#####----- Rule: os_mail_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_mail_app_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/Mail.app")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_mail_app_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_mail_app_disable -bool NO
else
    echo "os_mail_app_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_mail_app_disable -bool YES
fi

#####----- Rule: os_messages_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_messages_app_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/Messages.app")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_messages_app_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_messages_app_disable -bool NO
else
    echo "os_messages_app_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_messages_app_disable -bool YES
fi

#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a)
echo 'Running the command to check the settings for: os_nfsd_disable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => true')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_nfsd_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_nfsd_disable -bool NO
else
    echo "os_nfsd_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_nfsd_disable -bool YES
fi

#####----- Rule: os_password_autofill_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(a), CM-6(b)
echo 'Running the command to check the settings for: os_password_autofill_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordAutoFill = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_password_autofill_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_autofill_disable -bool NO
else
    echo "os_password_autofill_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_autofill_disable -bool YES
fi

#####----- Rule: os_password_proximity_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_password_proximity_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordProximityRequests = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_password_proximity_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_proximity_disable -bool NO
else
    echo "os_password_proximity_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_proximity_disable -bool YES
fi

#####----- Rule: os_password_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(5)(b), CM-7(a)
echo 'Running the command to check the settings for: os_password_sharing_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordSharing = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_password_sharing_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_sharing_disable -bool NO
else
    echo "os_password_sharing_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_password_sharing_disable -bool YES
fi

#####----- Rule: os_policy_banner_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-8(a), AC-8(b), AC-8(c)(1), AC-8(c)(2), AC-8(c)(3)
echo 'Running the command to check the settings for: os_policy_banner_loginwindow_enforce ...' | tee -a "$audit_log"
result_value=$(/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | tr -d ' ')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_policy_banner_loginwindow_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -bool NO
else
    echo "os_policy_banner_loginwindow_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -bool YES
fi

#####----- Rule: os_policy_banner_ssh_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AC-8(a)
echo 'Running the command to check the settings for: os_policy_banner_ssh_configure ...' | tee -a "$audit_log"
result_value=$(bannerText="You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all Government-furnished computers connected to this network, and 4) all Government-furnished devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; unauthorized use of the system is prohibited and subject to criminal and civil penalties; you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this information system at any time and for any lawful Government purpose, the Government may monitor, intercept, audit, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose. This information system may contain Controlled Unclassified Information (CUI) that is subject to safeguarding or dissemination controls in accordance with law, regulation, or Government-wide policy. Accessing and using this system indicates your understanding of this warning."
/usr/bin/grep -c "$bannerText" /etc/banner)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_policy_banner_ssh_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_policy_banner_ssh_configure -bool NO
else
    echo "os_policy_banner_ssh_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_policy_banner_ssh_configure -bool YES
fi

#####----- Rule: os_policy_banner_ssh_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-8(a), AC-8(b)
echo 'Running the command to check the settings for: os_policy_banner_ssh_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "^Banner /etc/banner" /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_policy_banner_ssh_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_policy_banner_ssh_enforce -bool NO
else
    echo "os_policy_banner_ssh_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_policy_banner_ssh_enforce -bool YES
fi

#####----- Rule: os_power_nap_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: os_power_nap_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/pmset -g custom | awk '/powernap/ { sum+=$2 } END {print sum}')
# expected result {'integer': 0}

if [[ $result_value == "0" ]]; then
    echo "os_power_nap_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_power_nap_disable -bool NO
else
    echo "os_power_nap_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_power_nap_disable -bool YES
fi

#####----- Rule: os_privacy_setup_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
## CM-7(a)
echo 'Running the command to check the settings for: os_privacy_setup_prompt_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipPrivacySetup = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_privacy_setup_prompt_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_privacy_setup_prompt_disable -bool NO
else
    echo "os_privacy_setup_prompt_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_privacy_setup_prompt_disable -bool YES
fi

#####----- Rule: os_removable_media_disable -----#####
## Addresses the following NIST 800-53 controls: 
## MP-7(1)
echo 'Running the command to check the settings for: os_removable_media_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep 'harddisk-external' -A3 | grep -Ec "eject|alert")
# expected result {'integer': 2}

if [[ $result_value == "2" ]]; then
    echo "os_removable_media_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_removable_media_disable -bool NO
else
    echo "os_removable_media_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_removable_media_disable -bool YES
fi

#####----- Rule: os_root_disable -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2
echo 'Running the command to check the settings for: os_root_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c "/usr/bin/false")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_root_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_root_disable -bool NO
else
    echo "os_root_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_root_disable -bool YES
fi

#####----- Rule: os_root_disable_sshd -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2
echo 'Running the command to check the settings for: os_root_disable_sshd ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c '^PermitRootLogin no' /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_root_disable_sshd passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_root_disable_sshd -bool NO
else
    echo "os_root_disable_sshd FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_root_disable_sshd -bool YES
fi

#####----- Rule: os_screensaver_ask_for_password_delay_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(b)
echo 'Running the command to check the settings for: os_screensaver_ask_for_password_delay_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'askForPasswordDelay = 5')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_screensaver_ask_for_password_delay_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_ask_for_password_delay_enforce -bool NO
else
    echo "os_screensaver_ask_for_password_delay_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_ask_for_password_delay_enforce -bool YES
fi

#####----- Rule: os_screensaver_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(1)
echo 'Running the command to check the settings for: os_screensaver_loginwindow_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout  | /usr/bin/grep -c loginWindowModulePath)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_screensaver_loginwindow_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_loginwindow_enforce -bool NO
else
    echo "os_screensaver_loginwindow_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_loginwindow_enforce -bool YES
fi

#####----- Rule: os_screensaver_password_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(b)
echo 'Running the command to check the settings for: os_screensaver_password_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'askForPassword = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_screensaver_password_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_password_enforce -bool NO
else
    echo "os_screensaver_password_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_password_enforce -bool YES
fi

#####----- Rule: os_screensaver_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-11(a)
echo 'Running the command to check the settings for: os_screensaver_timeout_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'idleTime = 900')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_screensaver_timeout_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_timeout_enforce -bool NO
else
    echo "os_screensaver_timeout_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_screensaver_timeout_enforce -bool YES
fi

#####----- Rule: os_secure_boot_verify -----#####
## Addresses the following NIST 800-53 controls: 
## SI-6(a), SI-6(b), SI-6(d)
echo 'Running the command to check the settings for: os_secure_boot_verify ...' | tee -a "$audit_log"
result_value=$(/usr/sbin/nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy | grep -c '%02')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_secure_boot_verify passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_secure_boot_verify -bool NO
else
    echo "os_secure_boot_verify FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_secure_boot_verify -bool YES
fi

#####----- Rule: os_siri_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-5(5)(b)
## CM-6(b)
## CM-7(a)
echo 'Running the command to check the settings for: os_siri_prompt_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipSiriSetup = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_siri_prompt_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_siri_prompt_disable -bool NO
else
    echo "os_siri_prompt_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_siri_prompt_disable -bool YES
fi

#####----- Rule: os_ssh_client_alive_count_max_configure -----#####
## Addresses the following NIST 800-53 controls: 
## SC-10
echo 'Running the command to check the settings for: os_ssh_client_alive_count_max_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "^ClientAliveCountMax 0" /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_ssh_client_alive_count_max_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_client_alive_count_max_configure -bool NO
else
    echo "os_ssh_client_alive_count_max_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_client_alive_count_max_configure -bool YES
fi

#####----- Rule: os_ssh_client_alive_interval_configure -----#####
## Addresses the following NIST 800-53 controls: 
## SC-10
echo 'Running the command to check the settings for: os_ssh_client_alive_interval_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "^ClientAliveInterval 900" /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_ssh_client_alive_interval_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_client_alive_interval_configure -bool NO
else
    echo "os_ssh_client_alive_interval_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_client_alive_interval_configure -bool YES
fi

#####----- Rule: os_ssh_fips_140_ciphers -----#####
## Addresses the following NIST 800-53 controls: 
## AC-17(2)
## CM-6(b)
## IA-7
echo 'Running the command to check the settings for: os_ssh_fips_140_ciphers ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "^Ciphers aes256-ctr,aes192-ctr,aes128-ctr" /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_ssh_fips_140_ciphers passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_fips_140_ciphers -bool NO
else
    echo "os_ssh_fips_140_ciphers FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_fips_140_ciphers -bool YES
fi

#####----- Rule: os_ssh_fips_140_macs -----#####
## Addresses the following NIST 800-53 controls: 
## AC-17(2)
## CM-6(b)
## IA-7
echo 'Running the command to check the settings for: os_ssh_fips_140_macs ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "^MACs hmac-sha2-256,hmac-sha2-512" /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_ssh_fips_140_macs passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_fips_140_macs -bool NO
else
    echo "os_ssh_fips_140_macs FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_fips_140_macs -bool YES
fi

#####----- Rule: os_ssh_login_grace_time_configure -----#####
## Addresses the following NIST 800-53 controls: 
## SC-10
echo 'Running the command to check the settings for: os_ssh_login_grace_time_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "^LoginGraceTime 30" /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_ssh_login_grace_time_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_login_grace_time_configure -bool NO
else
    echo "os_ssh_login_grace_time_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_login_grace_time_configure -bool YES
fi

#####----- Rule: os_ssh_max_sessions_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AC-10
echo 'Running the command to check the settings for: os_ssh_max_sessions_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -c "MaxSessions 10" /etc/ssh/sshd_config)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_ssh_max_sessions_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_max_sessions_configure -bool NO
else
    echo "os_ssh_max_sessions_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_ssh_max_sessions_configure -bool YES
fi

#####----- Rule: os_sudoers_tty_configure -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: os_sudoers_tty_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/grep -Ec "^Defaults tty_tickets" /etc/sudoers)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_sudoers_tty_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_sudoers_tty_configure -bool NO
else
    echo "os_sudoers_tty_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_sudoers_tty_configure -bool YES
fi

#####----- Rule: os_system_wide_preferences_configure -----#####
## Addresses the following NIST 800-53 controls: 
## AC-6, AC-6(1), AC-6(2)
echo 'Running the command to check the settings for: os_system_wide_preferences_configure ...' | tee -a "$audit_log"
result_value=$(/usr/bin/security authorizationdb read system.preferences 2> /dev/null |  grep -A 1 "<key>shared</key>" | grep -c "<false/>")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_system_wide_preferences_configure passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_system_wide_preferences_configure -bool NO
else
    echo "os_system_wide_preferences_configure FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_system_wide_preferences_configure -bool YES
fi

#####----- Rule: os_time_server_enabled -----#####
## Addresses the following NIST 800-53 controls: 
## AU-8(1)(a), AU-8(1)(b)
echo 'Running the command to check the settings for: os_time_server_enabled ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl list | /usr/bin/grep -c com.apple.timed)
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_time_server_enabled passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_time_server_enabled -bool NO
else
    echo "os_time_server_enabled FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_time_server_enabled -bool YES
fi

#####----- Rule: os_touchid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: os_touchid_prompt_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipTouchIDSetup = 1')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_touchid_prompt_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_touchid_prompt_disable -bool NO
else
    echo "os_touchid_prompt_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_touchid_prompt_disable -bool YES
fi

#####----- Rule: os_uamdm_require -----#####
## Addresses the following NIST 800-53 controls: 
## CM-6(b)
echo 'Running the command to check the settings for: os_uamdm_require ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles status -type enrollment | awk -F': ' 'END{print $2}' | grep -c "Yes")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_uamdm_require passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_uamdm_require -bool NO
else
    echo "os_uamdm_require FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_uamdm_require -bool YES
fi

#####----- Rule: os_unlock_active_user_session_disable -----#####
## Addresses the following NIST 800-53 controls: 
## IA-2, IA-2(5)
echo 'Running the command to check the settings for: os_unlock_active_user_session_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | grep -c 'use-login-window-ui')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_unlock_active_user_session_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_unlock_active_user_session_disable -bool NO
else
    echo "os_unlock_active_user_session_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_unlock_active_user_session_disable -bool YES
fi

#####----- Rule: os_uucp_disable -----#####
## Addresses the following NIST 800-53 controls: 
## CM-7(a), CM-7(b)
echo 'Running the command to check the settings for: os_uucp_disable ...' | tee -a "$audit_log"
result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.uucp" => true')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "os_uucp_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_uucp_disable -bool NO
else
    echo "os_uucp_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" os_uucp_disable -bool YES
fi

#####----- Rule: pwpolicy_60_day_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(d)
echo 'Running the command to check the settings for: pwpolicy_60_day_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | awk -F " = " '/maxPINAgeInDays/{sub(/;.*/,"");print $2}')
# expected result {'integer': 60}

if [[ $result_value == "60" ]]; then
    echo "pwpolicy_60_day_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_60_day_enforce -bool NO
else
    echo "pwpolicy_60_day_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_60_day_enforce -bool YES
fi

#####----- Rule: pwpolicy_account_inactivity_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-4(e)
echo 'Running the command to check the settings for: pwpolicy_account_inactivity_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="policyAttributeInactiveDays"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
# expected result {'integer': 35}

if [[ $result_value == "35" ]]; then
    echo "pwpolicy_account_inactivity_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -bool NO
else
    echo "pwpolicy_account_inactivity_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -bool YES
fi

#####----- Rule: pwpolicy_account_lockout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-7(a), AC-7(b)
echo 'Running the command to check the settings for: pwpolicy_account_lockout_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'maxFailedAttempts = 3')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_account_lockout_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_lockout_enforce -bool NO
else
    echo "pwpolicy_account_lockout_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_lockout_enforce -bool YES
fi

#####----- Rule: pwpolicy_account_lockout_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## AC-7(b)
echo 'Running the command to check the settings for: pwpolicy_account_lockout_timeout_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'minutesUntilFailedLoginReset = 15')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_account_lockout_timeout_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -bool NO
else
    echo "pwpolicy_account_lockout_timeout_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -bool YES
fi

#####----- Rule: pwpolicy_alpha_numeric_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(a)
echo 'Running the command to check the settings for: pwpolicy_alpha_numeric_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c "requireAlphanumeric = 1;")
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_alpha_numeric_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -bool NO
else
    echo "pwpolicy_alpha_numeric_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -bool YES
fi

#####----- Rule: pwpolicy_history_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(e), IA-5(e)
echo 'Running the command to check the settings for: pwpolicy_history_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk '/pinHistory/{sub(/;.*/,"");print $3}')
# expected result {'integer': 5}

if [[ $result_value == "5" ]]; then
    echo "pwpolicy_history_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_history_enforce -bool NO
else
    echo "pwpolicy_history_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_history_enforce -bool YES
fi

#####----- Rule: pwpolicy_lower_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(a)
echo 'Running the command to check the settings for: pwpolicy_lower_case_character_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="minimumAlphaCharactersLowerCase"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_lower_case_character_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -bool NO
else
    echo "pwpolicy_lower_case_character_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -bool YES
fi

#####----- Rule: pwpolicy_minimum_length_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(a)
echo 'Running the command to check the settings for: pwpolicy_minimum_length_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'minLength = 15')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_minimum_length_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_minimum_length_enforce -bool NO
else
    echo "pwpolicy_minimum_length_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_minimum_length_enforce -bool YES
fi

#####----- Rule: pwpolicy_minimum_lifetime_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(d)
echo 'Running the command to check the settings for: pwpolicy_minimum_lifetime_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="policyAttributeMinimumLifetimeHours"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
# expected result {'integer': 24}

if [[ $result_value == "24" ]]; then
    echo "pwpolicy_minimum_lifetime_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -bool NO
else
    echo "pwpolicy_minimum_lifetime_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -bool YES
fi

#####----- Rule: pwpolicy_simple_sequence_disable -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(a)
echo 'Running the command to check the settings for: pwpolicy_simple_sequence_disable ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowSimple = 0')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_simple_sequence_disable passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_simple_sequence_disable -bool NO
else
    echo "pwpolicy_simple_sequence_disable FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_simple_sequence_disable -bool YES
fi

#####----- Rule: pwpolicy_special_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(a)
echo 'Running the command to check the settings for: pwpolicy_special_character_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/awk '/minComplexChars/{sub(/;.*/,"");print $3}')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_special_character_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_special_character_enforce -bool NO
else
    echo "pwpolicy_special_character_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_special_character_enforce -bool YES
fi

#####----- Rule: pwpolicy_upper_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
## IA-5(1)(a)
echo 'Running the command to check the settings for: pwpolicy_upper_case_character_enforce ...' | tee -a "$audit_log"
result_value=$(/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v "Getting global account policies" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key="minimumAlphaCharactersUpperCase"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}')
# expected result {'integer': 1}

if [[ $result_value == "1" ]]; then
    echo "pwpolicy_upper_case_character_enforce passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -bool NO
else
    echo "pwpolicy_upper_case_character_enforce FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -bool YES
fi

lastComplianceScan=$(defaults read "$audit_plist" lastComplianceCheck)

}

run_scan
