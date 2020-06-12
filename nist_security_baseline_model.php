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

    ];
}
