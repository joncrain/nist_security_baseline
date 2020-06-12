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
    ];
});
