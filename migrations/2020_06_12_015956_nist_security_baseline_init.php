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

            $table->unique('serial_number');
            $table->index('audit_acls_files_configure');
            $table->index('audit_acls_files_mode_configure');
            $table->index('audit_acls_folder_wheel_configure');
            $table->index('audit_acls_folders_configure');
            $table->index('audit_acls_folders_mode_configure');

        });
    }
    
    public function down()
    {
        $capsule = new Capsule();
        $capsule::schema()->dropIfExists('nist_security_baseline');
    }
}
