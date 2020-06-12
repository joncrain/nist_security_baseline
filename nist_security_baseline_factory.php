<?php

// Database seeder
// Please visit https://github.com/fzaninotto/Faker for more options

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(Nist_security_baseline_model::class, function (Faker\Generator $faker) {

    return [
        'audit_acls_files_configure' => $faker->boolean(),
        'audit_acls_files_mode_configure' => $faker->boolean(),
        'audit_acls_folder_wheel_configure' => $faker->boolean(),
        'audit_acls_folders_configure' => $faker->boolean(),
        'audit_acls_folders_mode_configure' => $faker->boolean(),
        'audit_configure_capacity_notify' => $faker->boolean(),
        'audit_failure_halt' => $faker->boolean(),
        'audit_files_group_configure' => $faker->boolean(),
        'audit_files_owner_configure' => $faker->boolean(),
        'audit_flags_aa_configure' => $faker->boolean(),
        'audit_flags_ad_configure' => $faker->boolean(),
        'audit_flags_failed_file_read_restriction_enforced' => $faker->boolean(),
        'audit_flags_failed_file_write_access_restriction_enforced' => $faker->boolean(),
        'audit_flags_file_attr_mod_access_restriction_enforced' => $faker->boolean(),
        'audit_flags_lo_configure' => $faker->boolean(),
        'audit_folder_group_configure' => $faker->boolean(),
        'audit_folder_owner_configure' => $faker->boolean(),
        'audit_retention_one_week_configure' => $faker->boolean(),
        'audit_settings_failure_notify' => $faker->boolean(),
        'auth_pam_login_smartcard_enforce' => $faker->boolean(),
        'auth_pam_su_smartcard_enforce' => $faker->boolean(),
        'auth_pam_sudo_smartcard_enforce' => $faker->boolean(),
        'auth_smartcard_allow' => $faker->boolean(),
        'auth_smartcard_certificate_trust_enforce_high' => $faker->boolean(),
        'auth_smartcard_certificate_trust_enforce_moderate' => $faker->boolean(),
        'auth_smartcard_enforce' => $faker->boolean(),
        'auth_ssh_smartcard_enforce' => $faker->boolean(),
        'sysprefs_ad_tracking_disable' => $faker->boolean(),
        'sysprefs_afp_disable' => $faker->boolean(),
        'sysprefs_apple_watch_unlock_disable' => $faker->boolean(),
        'sysprefs_automatic_login_disable' => $faker->boolean(),
        'sysprefs_bluetooth_disable' => $faker->boolean(),
        'sysprefs_bluetooth_sharing_disable' => $faker->boolean(),
        'sysprefs_content_caching_disable' => $faker->boolean(),
        'sysprefs_diagnostics_reports_disable' => $faker->boolean(),
        'sysprefs_filevault_enforce' => $faker->boolean(),
        'sysprefs_find_my_disable' => $faker->boolean(),
        'sysprefs_firewall_enable' => $faker->boolean(),
        'sysprefs_firewall_stealth_mode_enable' => $faker->boolean(),
        'sysprefs_gatekeeper_identified_developers_allowed' => $faker->boolean(),
        'sysprefs_gatekeeper_override_disallow' => $faker->boolean(),
        'sysprefs_hot_corners_disable' => $faker->boolean(),
        'sysprefs_internet_sharing_disable' => $faker->boolean(),
        'sysprefs_location_services_disable' => $faker->boolean(),
        'sysprefs_loginwindow_prompt_username_password_enforce' => $faker->boolean(),
        'sysprefs_media_sharing_disabled' => $faker->boolean(),
        'sysprefs_password_hints_disable' => $faker->boolean(),
        'sysprefs_rae_disable' => $faker->boolean(),
        'sysprefs_screen_sharing_disable' => $faker->boolean(),
        'sysprefs_siri_disable' => $faker->boolean(),
        'sysprefs_smbd_disable' => $faker->boolean(),
        'sysprefs_ssh_enable' => $faker->boolean(),
        'sysprefs_time_server_configure' => $faker->boolean(),
        'sysprefs_time_server_enforce' => $faker->boolean(),
        'sysprefs_token_removal_enforce' => $faker->boolean(),
        'sysprefs_touchid_unlock_disable' => $faker->boolean(),
        'sysprefs_wifi_disable' => $faker->boolean(),
        'icloud_addressbook_disable' => $faker->boolean(),
        'icloud_calendar_disable' => $faker->boolean(),
        'icloud_mail_disable' => $faker->boolean(),
        'icloud_notes_disable' => $faker->boolean(),
        'icloud_reminders_disable' => $faker->boolean(),
        'icloud_appleid_prefpane_disable' => $faker->boolean(),
        'icloud_bookmarks_disable' => $faker->boolean(),
        'icloud_drive_disable' => $faker->boolean(),
        'icloud_keychain_disable' => $faker->boolean(),
        'icloud_photos_disable' => $faker->boolean(),
        'icloud_sync_disable' => $faker->boolean(),
        'os_sip_enable' => $faker->boolean(),
        'os_airdrop_disable' => $faker->boolean(),
        'os_appleid_prompt_disable' => $faker->boolean(),
        'os_bonjour_disable' => $faker->boolean(),
        'os_calendar_app_disable' => $faker->boolean(),
        'os_camera_disable' => $faker->boolean(),
        'os_certificate_authority_trust' => $faker->boolean(),
        'os_facetime_app_disable' => $faker->boolean(),
        'os_filevault_autologin_disable' => $faker->boolean(),
        'os_firewall_default_deny_require' => $faker->boolean(),
        'os_firewall_log_enable' => $faker->boolean(),
        'os_firmware_password_require' => $faker->boolean(),
        'os_gatekeeper_enable' => $faker->boolean(),
        'os_guest_access_afp_disable' => $faker->boolean(),
        'os_guest_access_smb_disable' => $faker->boolean(),
        'os_guest_account_disable' => $faker->boolean(),
        'os_handoff_disable' => $faker->boolean(),
        'os_home_folders_secure' => $faker->boolean(),
        'os_httpd_disable' => $faker->boolean(),
        'os_icloud_storage_prompt_disable' => $faker->boolean(),
        'os_internet_accounts_prefpane_disable' => $faker->boolean(),
        'os_ir_support_disable' => $faker->boolean(),
        'os_mail_app_disable' => $faker->boolean(),
        'os_messages_app_disable' => $faker->boolean(),
        'os_nfsd_disable' => $faker->boolean(),
        'os_parental_controls_enable' => $faker->boolean(),
        'os_password_autofill_disable' => $faker->boolean(),
        'os_password_proximity_disable' => $faker->boolean(),
        'os_password_sharing_disable' => $faker->boolean(),
        'os_policy_banner_loginwindow_enforce' => $faker->boolean(),
        'os_policy_banner_ssh_configure' => $faker->boolean(),
        'os_policy_banner_ssh_enforce' => $faker->boolean(),
        'os_power_nap_disable' => $faker->boolean(),
        'os_privacy_setup_prompt_disable' => $faker->boolean(),
        'os_removable_media_disable' => $faker->boolean(),
        'os_root_disable' => $faker->boolean(),
        'os_root_disable_sshd' => $faker->boolean(),
        'os_screensaver_ask_for_password_delay_enforce' => $faker->boolean(),
        'os_screensaver_loginwindow_enforce' => $faker->boolean(),
        'os_screensaver_password_enforce' => $faker->boolean(),
        'os_screensaver_timeout_enforce' => $faker->boolean(),
        'os_secure_boot_verify' => $faker->boolean(),
        'os_siri_prompt_disable' => $faker->boolean(),
        'os_ssh_client_alive_count_max_configure' => $faker->boolean(),
        'os_ssh_client_alive_interval_configure' => $faker->boolean(),
        'os_ssh_fips_140_ciphers' => $faker->boolean(),
        'os_ssh_fips_140_macs' => $faker->boolean(),
        'os_ssh_login_grace_time_configure' => $faker->boolean(),
        'os_ssh_max_sessions_configure' => $faker->boolean(),
        'os_ssh_permit_root_login_configure' => $faker->boolean(),
        'os_sudoers_tty_configure' => $faker->boolean(),
        'os_system_wide_preferences_configure' => $faker->boolean(),
        'os_time_server_enabled' => $faker->boolean(),
        'os_touchid_prompt_disable' => $faker->boolean(),
        'os_uamdm_require' => $faker->boolean(),
        'os_unlock_active_user_session_disable' => $faker->boolean(),
        'os_user_app_installation_prohibit' => $faker->boolean(),
        'os_uucp_disable' => $faker->boolean(),
        'pwpolicy_60_day_enforce' => $faker->boolean(),
        'pwpolicy_account_inactivity_enforce' => $faker->boolean(),
        'pwpolicy_account_lockout_enforce' => $faker->boolean(),
        'pwpolicy_account_lockout_timeout_enforce' => $faker->boolean(),
        'pwpolicy_alpha_numeric_enforce' => $faker->boolean(),
        'pwpolicy_emergency_accounts_disable' => $faker->boolean(),
        'pwpolicy_history_enforce' => $faker->boolean(),
        'pwpolicy_lower_case_character_enforce' => $faker->boolean(),
        'pwpolicy_minimum_length_enforce' => $faker->boolean(),
        'pwpolicy_minimum_lifetime_enforce' => $faker->boolean(),
        'pwpolicy_simple_sequence_disable' => $faker->boolean(),
        'pwpolicy_special_character_enforce' => $faker->boolean(),
        'pwpolicy_temporary_accounts_disable' => $faker->boolean(),
        'pwpolicy_upper_case_character_enforce' => $faker->boolean(),
        'audit_alert_processing_fail' => $faker->boolean(),
        'audit_enforce_dual_auth' => $faker->boolean(),
        'audit_off_load_records' => $faker->boolean(),
        'os_enforce_login_attempt_delay' => $faker->boolean(),
        'os_limit_dos_attacks' => $faker->boolean(),
        'os_limit_invalid_logons' => $faker->boolean(),
        'os_notify_account_created' => $faker->boolean(),
        'os_notify_account_disabled' => $faker->boolean(),
        'os_notify_account_enable' => $faker->boolean(),
        'os_notify_account_modified' => $faker->boolean(),
        'os_notify_account_removal' => $faker->boolean(),
        'os_notify_unauthorized_baseline_change' => $faker->boolean(),
        'os_protect_dos_attacks' => $faker->boolean(),
        'os_provide_automated_account_management' => $faker->boolean(),
        'os_reauth_devices_change_authenticators' => $faker->boolean(),
        'pwpolicy_50_percent' => $faker->boolean(),
        'pwpolicy_prevent_dictionary_words' => $faker->boolean(),
        'pwpolicy_force_password_change' => $faker->boolean(),
        'os_auth_peripherals' => $faker->boolean(),
        'os_identify_non-org_users' => $faker->boolean(),
        'os_prohibit_cached_authenticators' => $faker->boolean(),
        'os_react_security_anomalies' => $faker->boolean(),
        'os_request_verification_name_resolution' => $faker->boolean(),
        'os_verify_security_functions' => $faker->boolean(),
        'audit_auditd_enabled' => $faker->boolean(),
        'os_allow_info_passed' => $faker->boolean(),
        'os_change_security_attributes' => $faker->boolean(),
        'os_crypto_audit' => $faker->boolean(),
        'os_enforce_access_restrictions' => $faker->boolean(),
        'os_error_message' => $faker->boolean(),
        'os_fail_secure_state' => $faker->boolean(),
        'os_grant_privs' => $faker->boolean(),
        'os_implement_memory_protection' => $faker->boolean(),
        'os_implement_cryptography' => $faker->boolean(),
        'os_implement_random_address_space' => $faker->boolean(),
        'os_isolate_security_functions' => $faker->boolean(),
        'os_limit_auditable_events' => $faker->boolean(),
        'os_limit_gui_sessions' => $faker->boolean(),
        'os_logical_access' => $faker->boolean(),
        'os_logoff_capability_and_message' => $faker->boolean(),
        'os_map_pki_identity' => $faker->boolean(),
        'os_mfa_network_access' => $faker->boolean(),
        'os_mfa_network_non-priv' => $faker->boolean(),
        'os_obscure_password' => $faker->boolean(),
        'os_peripherals_identify' => $faker->boolean(),
        'os_predictable_behavior' => $faker->boolean(),
        'os_preserve_information_on_crash' => $faker->boolean(),
        'os_prevent_priv_execution' => $faker->boolean(),
        'os_prevent_priv_functions' => $faker->boolean(),
        'os_prevent_restricted_software' => $faker->boolean(),
        'os_prevent_unauthorized_disclosure' => $faker->boolean(),
        'os_provide_disconnect_remote_access' => $faker->boolean(),
        'os_reauth_privilege' => $faker->boolean(),
        'os_reauth_users_change_authenticators' => $faker->boolean(),
        'os_remote_access_methods' => $faker->boolean(),
        'os_remove_software_components_after_updates' => $faker->boolean(),
        'os_required_crypto_module' => $faker->boolean(),
        'os_separate_fuctionality' => $faker->boolean(),
        'os_store_encrypted_passwords' => $faker->boolean(),
        'os_terminate_session' => $faker->boolean(),
        'os_terminate_session_inactivity' => $faker->boolean(),
        'os_unique_identification' => $faker->boolean(),
        'os_verify_remote_disconnection' => $faker->boolean(),
        'supplemental_smartcard' => $faker->boolean(),
        'supplemental_firewall_pf' => $faker->boolean(),
        'supplemental_password_policy' => $faker->boolean(),
    ];
});
