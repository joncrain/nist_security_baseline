<?php

use munkireport\models\MRModel as Eloquent;

class Nist_security_baseline_model extends Eloquent
{
    protected $table = 'nist_security_baseline';

    protected $hidden = ['id', 'serial_number'];

    protected $fillable = [
      'serial_number',
      'audit_acls_files_configure',
      'audit_acls_files_mode_configure',
      'audit_acls_folder_wheel_configure',
      'audit_acls_folders_configure',
      'audit_acls_folders_mode_configure',
      'audit_configure_capacity_notify',
      'audit_failure_halt',
      'audit_files_group_configure',
      'audit_files_owner_configure',
      'audit_flags_aa_configure',
      'audit_flags_ad_configure',
      'audit_flags_failed_file_read_restriction_enforced',
      'audit_flags_failed_file_write_access_restriction_enforced',
      'audit_flags_file_attr_mod_access_restriction_enforced',
      'audit_flags_lo_configure',
      'audit_folder_group_configure',
      'audit_folder_owner_configure',
      'audit_retention_one_week_configure',
      'audit_settings_failure_notify',
      'auth_pam_login_smartcard_enforce',
      'auth_pam_su_smartcard_enforce',
      'auth_pam_sudo_smartcard_enforce',
      'auth_smartcard_allow',
      'auth_smartcard_certificate_trust_enforce_high',
      'auth_smartcard_certificate_trust_enforce_moderate',
      'auth_smartcard_enforce',
      'auth_ssh_smartcard_enforce',
      'sysprefs_ad_tracking_disable',
      'sysprefs_afp_disable',
      'sysprefs_apple_watch_unlock_disable',
      'sysprefs_automatic_login_disable',
      'sysprefs_bluetooth_disable',
      'sysprefs_bluetooth_sharing_disable',
      'sysprefs_content_caching_disable',
      'sysprefs_diagnostics_reports_disable',
      'sysprefs_filevault_enforce',
      'sysprefs_find_my_disable',
      'sysprefs_firewall_enable',
      'sysprefs_firewall_stealth_mode_enable',
      'sysprefs_gatekeeper_identified_developers_allowed',
      'sysprefs_gatekeeper_override_disallow',
      'sysprefs_hot_corners_disable',
      'sysprefs_internet_sharing_disable',
      'sysprefs_location_services_disable',
      'sysprefs_loginwindow_prompt_username_password_enforce',
      'sysprefs_media_sharing_disabled',
      'sysprefs_password_hints_disable',
      'sysprefs_rae_disable',
      'sysprefs_screen_sharing_disable',
      'sysprefs_siri_disable',
      'sysprefs_smbd_disable',
      'sysprefs_ssh_enable',
      'sysprefs_time_server_configure',
      'sysprefs_time_server_enforce',
      'sysprefs_token_removal_enforce',
      'sysprefs_touchid_unlock_disable',
      'sysprefs_wifi_disable',
      'icloud_addressbook_disable',
      'icloud_calendar_disable',
      'icloud_mail_disable',
      'icloud_notes_disable',
      'icloud_reminders_disable',
      'icloud_appleid_prefpane_disable',
      'icloud_bookmarks_disable',
      'icloud_drive_disable',
      'icloud_keychain_disable',
      'icloud_photos_disable',
      'icloud_sync_disable',
      'os_sip_enable',
      'os_airdrop_disable',
      'os_appleid_prompt_disable',
      'os_bonjour_disable',
      'os_calendar_app_disable',
      'os_camera_disable',
      'os_certificate_authority_trust',
      'os_facetime_app_disable',
      'os_filevault_autologin_disable',
      'os_firewall_default_deny_require',
      'os_firewall_log_enable',
      'os_firmware_password_require',
      'os_gatekeeper_enable',
      'os_guest_access_afp_disable',
      'os_guest_access_smb_disable',
      'os_guest_account_disable',
      'os_handoff_disable',
      'os_home_folders_secure',
      'os_httpd_disable',
      'os_icloud_storage_prompt_disable',
      'os_internet_accounts_prefpane_disable',
      'os_ir_support_disable',
      'os_mail_app_disable',
      'os_messages_app_disable',
      'os_nfsd_disable',
      'os_parental_controls_enable',
      'os_password_autofill_disable',
      'os_password_proximity_disable',
      'os_password_sharing_disable',
      'os_policy_banner_loginwindow_enforce',
      'os_policy_banner_ssh_configure',
      'os_policy_banner_ssh_enforce',
      'os_power_nap_disable',
      'os_privacy_setup_prompt_disable',
      'os_removable_media_disable',
      'os_root_disable',
      'os_root_disable_sshd',
      'os_screensaver_ask_for_password_delay_enforce',
      'os_screensaver_loginwindow_enforce',
      'os_screensaver_password_enforce',
      'os_screensaver_timeout_enforce',
      'os_secure_boot_verify',
      'os_siri_prompt_disable',
      'os_ssh_client_alive_count_max_configure',
      'os_ssh_client_alive_interval_configure',
      'os_ssh_fips_140_ciphers',
      'os_ssh_fips_140_macs',
      'os_ssh_login_grace_time_configure',
      'os_ssh_max_sessions_configure',
      'os_ssh_permit_root_login_configure',
      'os_sudoers_tty_configure',
      'os_system_wide_preferences_configure',
      'os_time_server_enabled',
      'os_touchid_prompt_disable',
      'os_uamdm_require',
      'os_unlock_active_user_session_disable',
      'os_user_app_installation_prohibit',
      'os_uucp_disable',
      'pwpolicy_60_day_enforce',
      'pwpolicy_account_inactivity_enforce',
      'pwpolicy_account_lockout_enforce',
      'pwpolicy_account_lockout_timeout_enforce',
      'pwpolicy_alpha_numeric_enforce',
      'pwpolicy_emergency_accounts_disable',
      'pwpolicy_history_enforce',
      'pwpolicy_lower_case_character_enforce',
      'pwpolicy_minimum_length_enforce',
      'pwpolicy_minimum_lifetime_enforce',
      'pwpolicy_simple_sequence_disable',
      'pwpolicy_special_character_enforce',
      'pwpolicy_temporary_accounts_disable',
      'pwpolicy_upper_case_character_enforce',
      'audit_alert_processing_fail',
      'audit_enforce_dual_auth',
      'audit_off_load_records',
      'os_enforce_login_attempt_delay',
      'os_limit_dos_attacks',
      'os_limit_invalid_logons',
      'os_notify_account_created',
      'os_notify_account_disabled',
      'os_notify_account_enable',
      'os_notify_account_modified',
      'os_notify_account_removal',
      'os_notify_unauthorized_baseline_change',
      'os_protect_dos_attacks',
      'os_provide_automated_account_management',
      'os_reauth_devices_change_authenticators',
      'pwpolicy_50_percent',
      'pwpolicy_prevent_dictionary_words',
      'pwpolicy_force_password_change',
      'os_auth_peripherals',
      'os_identify_non-org_users',
      'os_prohibit_cached_authenticators',
      'os_react_security_anomalies',
      'os_request_verification_name_resolution',
      'os_verify_security_functions',
      'audit_auditd_enabled',
      'os_allow_info_passed',
      'os_change_security_attributes',
      'os_crypto_audit',
      'os_enforce_access_restrictions',
      'os_error_message',
      'os_fail_secure_state',
      'os_grant_privs',
      'os_implement_memory_protection',
      'os_implement_cryptography',
      'os_implement_random_address_space',
      'os_isolate_security_functions',
      'os_limit_auditable_events',
      'os_limit_gui_sessions',
      'os_logical_access',
      'os_logoff_capability_and_message',
      'os_map_pki_identity',
      'os_mfa_network_access',
      'os_mfa_network_non-priv',
      'os_obscure_password',
      'os_peripherals_identify',
      'os_predictable_behavior',
      'os_preserve_information_on_crash',
      'os_prevent_priv_execution',
      'os_prevent_priv_functions',
      'os_prevent_restricted_software',
      'os_prevent_unauthorized_disclosure',
      'os_provide_disconnect_remote_access',
      'os_reauth_privilege',
      'os_reauth_users_change_authenticators',
      'os_remote_access_methods',
      'os_remove_software_components_after_updates',
      'os_required_crypto_module',
      'os_separate_fuctionality',
      'os_store_encrypted_passwords',
      'os_terminate_session',
      'os_terminate_session_inactivity',
      'os_unique_identification',
      'os_verify_remote_disconnection',
      'supplemental_smartcard',
      'supplemental_firewall_pf',
      'supplemental_password_policy',

    ];
}
