<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Capsule\Manager as Capsule;

class NistSecurityBaselineInit extends Migration
{
    public function up()
    {
        $capsule = new Capsule();
        $capsule::schema()->create('nist_security_baseline', function (Blueprint $table) {
            $table->increments('id');
            $table->string('serial_number');
            $table->boolean('audit_acls_files_configure')->nullable();
            $table->boolean('audit_acls_files_mode_configure')->nullable();
            $table->boolean('audit_acls_folder_wheel_configure')->nullable();
            $table->boolean('audit_acls_folders_configure')->nullable();
            $table->boolean('audit_acls_folders_mode_configure')->nullable();
            $table->boolean('audit_configure_capacity_notify')->nullable();
            $table->boolean('audit_failure_halt')->nullable();
            $table->boolean('audit_files_group_configure')->nullable();
            $table->boolean('audit_files_owner_configure')->nullable();
            $table->boolean('audit_flags_aa_configure')->nullable();
            $table->boolean('audit_flags_ad_configure')->nullable();
            $table->boolean('audit_flags_failed_file_read_restriction_enforced')->nullable();
            $table->boolean('audit_flags_failed_file_write_access_restriction_enforced')->nullable();
            $table->boolean('audit_flags_file_attr_mod_access_restriction_enforced')->nullable();
            $table->boolean('audit_flags_lo_configure')->nullable();
            $table->boolean('audit_folder_group_configure')->nullable();
            $table->boolean('audit_folder_owner_configure')->nullable();
            $table->boolean('audit_retention_one_week_configure')->nullable();
            $table->boolean('audit_settings_failure_notify')->nullable();
            $table->boolean('auth_pam_login_smartcard_enforce')->nullable();
            $table->boolean('auth_pam_su_smartcard_enforce')->nullable();
            $table->boolean('auth_pam_sudo_smartcard_enforce')->nullable();
            $table->boolean('auth_smartcard_allow')->nullable();
            $table->boolean('auth_smartcard_certificate_trust_enforce_high')->nullable();
            $table->boolean('auth_smartcard_certificate_trust_enforce_moderate')->nullable();
            $table->boolean('auth_smartcard_enforce')->nullable();
            $table->boolean('auth_ssh_smartcard_enforce')->nullable();
            $table->boolean('sysprefs_ad_tracking_disable')->nullable();
            $table->boolean('sysprefs_afp_disable')->nullable();
            $table->boolean('sysprefs_apple_watch_unlock_disable')->nullable();
            $table->boolean('sysprefs_automatic_login_disable')->nullable();
            $table->boolean('sysprefs_bluetooth_disable')->nullable();
            $table->boolean('sysprefs_bluetooth_sharing_disable')->nullable();
            $table->boolean('sysprefs_content_caching_disable')->nullable();
            $table->boolean('sysprefs_diagnostics_reports_disable')->nullable();
            $table->boolean('sysprefs_filevault_enforce')->nullable();
            $table->boolean('sysprefs_find_my_disable')->nullable();
            $table->boolean('sysprefs_firewall_enable')->nullable();
            $table->boolean('sysprefs_firewall_stealth_mode_enable')->nullable();
            $table->boolean('sysprefs_gatekeeper_identified_developers_allowed')->nullable();
            $table->boolean('sysprefs_gatekeeper_override_disallow')->nullable();
            $table->boolean('sysprefs_hot_corners_disable')->nullable();
            $table->boolean('sysprefs_internet_sharing_disable')->nullable();
            $table->boolean('sysprefs_location_services_disable')->nullable();
            $table->boolean('sysprefs_loginwindow_prompt_username_password_enforce')->nullable();
            $table->boolean('sysprefs_media_sharing_disabled')->nullable();
            $table->boolean('sysprefs_password_hints_disable')->nullable();
            $table->boolean('sysprefs_rae_disable')->nullable();
            $table->boolean('sysprefs_screen_sharing_disable')->nullable();
            $table->boolean('sysprefs_siri_disable')->nullable();
            $table->boolean('sysprefs_smbd_disable')->nullable();
            $table->boolean('sysprefs_ssh_enable')->nullable();
            $table->boolean('sysprefs_time_server_configure')->nullable();
            $table->boolean('sysprefs_time_server_enforce')->nullable();
            $table->boolean('sysprefs_token_removal_enforce')->nullable();
            $table->boolean('sysprefs_touchid_unlock_disable')->nullable();
            $table->boolean('sysprefs_wifi_disable')->nullable();
            $table->boolean('icloud_addressbook_disable')->nullable();
            $table->boolean('icloud_calendar_disable')->nullable();
            $table->boolean('icloud_mail_disable')->nullable();
            $table->boolean('icloud_notes_disable')->nullable();
            $table->boolean('icloud_reminders_disable')->nullable();
            $table->boolean('icloud_appleid_prefpane_disable')->nullable();
            $table->boolean('icloud_bookmarks_disable')->nullable();
            $table->boolean('icloud_drive_disable')->nullable();
            $table->boolean('icloud_keychain_disable')->nullable();
            $table->boolean('icloud_photos_disable')->nullable();
            $table->boolean('icloud_sync_disable')->nullable();
            $table->boolean('os_sip_enable')->nullable();
            $table->boolean('os_airdrop_disable')->nullable();
            $table->boolean('os_appleid_prompt_disable')->nullable();
            $table->boolean('os_bonjour_disable')->nullable();
            $table->boolean('os_calendar_app_disable')->nullable();
            $table->boolean('os_camera_disable')->nullable();
            $table->boolean('os_certificate_authority_trust')->nullable();
            $table->boolean('os_facetime_app_disable')->nullable();
            $table->boolean('os_filevault_autologin_disable')->nullable();
            $table->boolean('os_firewall_default_deny_require')->nullable();
            $table->boolean('os_firewall_log_enable')->nullable();
            $table->boolean('os_firmware_password_require')->nullable();
            $table->boolean('os_gatekeeper_enable')->nullable();
            $table->boolean('os_guest_access_afp_disable')->nullable();
            $table->boolean('os_guest_access_smb_disable')->nullable();
            $table->boolean('os_guest_account_disable')->nullable();
            $table->boolean('os_handoff_disable')->nullable();
            $table->boolean('os_home_folders_secure')->nullable();
            $table->boolean('os_httpd_disable')->nullable();
            $table->boolean('os_icloud_storage_prompt_disable')->nullable();
            $table->boolean('os_internet_accounts_prefpane_disable')->nullable();
            $table->boolean('os_ir_support_disable')->nullable();
            $table->boolean('os_mail_app_disable')->nullable();
            $table->boolean('os_messages_app_disable')->nullable();
            $table->boolean('os_nfsd_disable')->nullable();
            $table->boolean('os_parental_controls_enable')->nullable();
            $table->boolean('os_password_autofill_disable')->nullable();
            $table->boolean('os_password_proximity_disable')->nullable();
            $table->boolean('os_password_sharing_disable')->nullable();
            $table->boolean('os_policy_banner_loginwindow_enforce')->nullable();
            $table->boolean('os_policy_banner_ssh_configure')->nullable();
            $table->boolean('os_policy_banner_ssh_enforce')->nullable();
            $table->boolean('os_power_nap_disable')->nullable();
            $table->boolean('os_privacy_setup_prompt_disable')->nullable();
            $table->boolean('os_removable_media_disable')->nullable();
            $table->boolean('os_root_disable')->nullable();
            $table->boolean('os_root_disable_sshd')->nullable();
            $table->boolean('os_screensaver_ask_for_password_delay_enforce')->nullable();
            $table->boolean('os_screensaver_loginwindow_enforce')->nullable();
            $table->boolean('os_screensaver_password_enforce')->nullable();
            $table->boolean('os_screensaver_timeout_enforce')->nullable();
            $table->boolean('os_secure_boot_verify')->nullable();
            $table->boolean('os_siri_prompt_disable')->nullable();
            $table->boolean('os_ssh_client_alive_count_max_configure')->nullable();
            $table->boolean('os_ssh_client_alive_interval_configure')->nullable();
            $table->boolean('os_ssh_fips_140_ciphers')->nullable();
            $table->boolean('os_ssh_fips_140_macs')->nullable();
            $table->boolean('os_ssh_login_grace_time_configure')->nullable();
            $table->boolean('os_ssh_max_sessions_configure')->nullable();
            $table->boolean('os_ssh_permit_root_login_configure')->nullable();
            $table->boolean('os_sudoers_tty_configure')->nullable();
            $table->boolean('os_system_wide_preferences_configure')->nullable();
            $table->boolean('os_time_server_enabled')->nullable();
            $table->boolean('os_touchid_prompt_disable')->nullable();
            $table->boolean('os_uamdm_require')->nullable();
            $table->boolean('os_unlock_active_user_session_disable')->nullable();
            $table->boolean('os_user_app_installation_prohibit')->nullable();
            $table->boolean('os_uucp_disable')->nullable();
            $table->boolean('pwpolicy_60_day_enforce')->nullable();
            $table->boolean('pwpolicy_account_inactivity_enforce')->nullable();
            $table->boolean('pwpolicy_account_lockout_enforce')->nullable();
            $table->boolean('pwpolicy_account_lockout_timeout_enforce')->nullable();
            $table->boolean('pwpolicy_alpha_numeric_enforce')->nullable();
            $table->boolean('pwpolicy_emergency_accounts_disable')->nullable();
            $table->boolean('pwpolicy_history_enforce')->nullable();
            $table->boolean('pwpolicy_lower_case_character_enforce')->nullable();
            $table->boolean('pwpolicy_minimum_length_enforce')->nullable();
            $table->boolean('pwpolicy_minimum_lifetime_enforce')->nullable();
            $table->boolean('pwpolicy_simple_sequence_disable')->nullable();
            $table->boolean('pwpolicy_special_character_enforce')->nullable();
            $table->boolean('pwpolicy_temporary_accounts_disable')->nullable();
            $table->boolean('pwpolicy_upper_case_character_enforce')->nullable();
            $table->boolean('audit_alert_processing_fail')->nullable();
            $table->boolean('audit_enforce_dual_auth')->nullable();
            $table->boolean('audit_off_load_records')->nullable();
            $table->boolean('os_enforce_login_attempt_delay')->nullable();
            $table->boolean('os_limit_dos_attacks')->nullable();
            $table->boolean('os_limit_invalid_logons')->nullable();
            $table->boolean('os_notify_account_created')->nullable();
            $table->boolean('os_notify_account_disabled')->nullable();
            $table->boolean('os_notify_account_enable')->nullable();
            $table->boolean('os_notify_account_modified')->nullable();
            $table->boolean('os_notify_account_removal')->nullable();
            $table->boolean('os_notify_unauthorized_baseline_change')->nullable();
            $table->boolean('os_protect_dos_attacks')->nullable();
            $table->boolean('os_provide_automated_account_management')->nullable();
            $table->boolean('os_reauth_devices_change_authenticators')->nullable();
            $table->boolean('pwpolicy_50_percent')->nullable();
            $table->boolean('pwpolicy_prevent_dictionary_words')->nullable();
            $table->boolean('pwpolicy_force_password_change')->nullable();
            $table->boolean('os_auth_peripherals')->nullable();
            $table->boolean('os_identify_non-org_users')->nullable();
            $table->boolean('os_prohibit_cached_authenticators')->nullable();
            $table->boolean('os_react_security_anomalies')->nullable();
            $table->boolean('os_request_verification_name_resolution')->nullable();
            $table->boolean('os_verify_security_functions')->nullable();
            $table->boolean('audit_auditd_enabled')->nullable();
            $table->boolean('os_allow_info_passed')->nullable();
            $table->boolean('os_change_security_attributes')->nullable();
            $table->boolean('os_crypto_audit')->nullable();
            $table->boolean('os_enforce_access_restrictions')->nullable();
            $table->boolean('os_error_message')->nullable();
            $table->boolean('os_fail_secure_state')->nullable();
            $table->boolean('os_grant_privs')->nullable();
            $table->boolean('os_implement_memory_protection')->nullable();
            $table->boolean('os_implement_cryptography')->nullable();
            $table->boolean('os_implement_random_address_space')->nullable();
            $table->boolean('os_isolate_security_functions')->nullable();
            $table->boolean('os_limit_auditable_events')->nullable();
            $table->boolean('os_limit_gui_sessions')->nullable();
            $table->boolean('os_logical_access')->nullable();
            $table->boolean('os_logoff_capability_and_message')->nullable();
            $table->boolean('os_map_pki_identity')->nullable();
            $table->boolean('os_mfa_network_access')->nullable();
            $table->boolean('os_mfa_network_non-priv')->nullable();
            $table->boolean('os_obscure_password')->nullable();
            $table->boolean('os_peripherals_identify')->nullable();
            $table->boolean('os_predictable_behavior')->nullable();
            $table->boolean('os_preserve_information_on_crash')->nullable();
            $table->boolean('os_prevent_priv_execution')->nullable();
            $table->boolean('os_prevent_priv_functions')->nullable();
            $table->boolean('os_prevent_restricted_software')->nullable();
            $table->boolean('os_prevent_unauthorized_disclosure')->nullable();
            $table->boolean('os_provide_disconnect_remote_access')->nullable();
            $table->boolean('os_reauth_privilege')->nullable();
            $table->boolean('os_reauth_users_change_authenticators')->nullable();
            $table->boolean('os_remote_access_methods')->nullable();
            $table->boolean('os_remove_software_components_after_updates')->nullable();
            $table->boolean('os_required_crypto_module')->nullable();
            $table->boolean('os_separate_fuctionality')->nullable();
            $table->boolean('os_store_encrypted_passwords')->nullable();
            $table->boolean('os_terminate_session')->nullable();
            $table->boolean('os_terminate_session_inactivity')->nullable();
            $table->boolean('os_unique_identification')->nullable();
            $table->boolean('os_verify_remote_disconnection')->nullable();
            $table->boolean('supplemental_smartcard')->nullable();
            $table->boolean('supplemental_firewall_pf')->nullable();
            $table->boolean('supplemental_password_policy')->nullable();

            $table->unique('serial_number');

        });
    }
    
    public function down()
    {
        $capsule = new Capsule();
        $capsule::schema()->dropIfExists('nist_security_baseline');
    }
}
