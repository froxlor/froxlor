<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can also view it online at
 * https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  the authors
 * @author     froxlor team <team@froxlor.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 */

use Froxlor\Froxlor;

$httpuser = '';
$httpgroup = '';
if (extension_loaded('posix')) {
	$httpuser = posix_getpwuid(posix_getuid())['name'] ?? '';
	$httpgroup = posix_getgrgid(posix_getgid())['name'] ?? '';
}

return [
	'install' => [
		'title' => 'install',
		'sections' => [
			'step1' => [
				'title' => lng('install.database.title'),
				'description' => lng('install.database.description'),
				'fields' => [
					'mysql_host' => [
						'label' => lng('mysql.mysql_server'),
						'placeholder' => lng('mysql.mysql_server'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('mysql_host', 'localhost', 'installation')
					],
					'mysql_ssl_ca_file' => [
						'label' => lng('mysql.mysql_ssl_ca_file'),
						'placeholder' => lng('mysql.mysql_ssl_ca_file'),
						'type' => 'text',
						'value' => old('mysql_ssl_ca_file', null, 'installation'),
						'advanced' => true,
					],
					'mysql_ssl_verify_server_certificate' => [
						'label' => lng('mysql.mysql_ssl_verify_server_certificate'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => old('mysql_ssl_verify_server_certificate', '0', 'installation'),
						'advanced' => true,
					],
					'mysql_root_user' => [
						'label' => lng('mysql.privileged_user'),
						'placeholder' => lng('mysql.privileged_user'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('mysql_root_user', 'froxroot', 'installation'),
					],
					'mysql_root_pass' => [
						'label' => lng('mysql.privileged_passwd'),
						'placeholder' => lng('mysql.privileged_passwd'),
						'type' => 'password',
						'mandatory' => true,
						'value' => old('mysql_root_pass', null, 'installation'),
					],
					'mysql_unprivileged_user' => [
						'label' => lng('install.database.user'),
						'placeholder' => lng('install.database.user'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('mysql_unprivileged_user', 'froxlor', 'installation'),
					],
					'mysql_unprivileged_pass' => [
						'label' => lng('mysql.unprivileged_passwd'),
						'placeholder' => lng('mysql.unprivileged_passwd'),
						'type' => 'password',
						'mandatory' => true,
						'value' => old('mysql_unprivileged_pass', null, 'installation'),
					],
					'mysql_database' => [
						'label' => lng('install.database.dbname'),
						'placeholder' => lng('install.database.dbname'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('mysql_database', 'froxlor', 'installation'),
					],
					'mysql_force_create' => [
						'label' => lng('install.database.force_create'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => old('mysql_force_create', '0', 'installation')
					],
				]
			],
			'step2' => [
				'title' => lng('install.admin.title'),
				'description' => lng('install.admin.description'),
				'fields' => [
					'admin_name' => [
						'label' => lng('customer.name'),
						'placeholder' => lng('customer.name'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('admin_name', 'Administrator', 'installation'),
					],
					'admin_user' => [
						'label' => lng('login.username'),
						'placeholder' => lng('login.username'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('admin_user', 'admin', 'installation'),
					],
					'admin_pass' => [
						'label' => lng('login.password'),
						'placeholder' => lng('login.password'),
						'type' => 'password',
						'mandatory' => true,
						'value' => old('admin_pass', null, 'installation'),
					],
					'admin_pass_confirm' => [
						'label' => lng('changepassword.new_password_confirm'),
						'placeholder' => lng('changepassword.new_password_confirm'),
						'type' => 'password',
						'mandatory' => true,
						'value' => old('admin_pass_confirm', null, 'installation'),
					],
					'admin_email' => [
						'label' => lng('customer.email'),
						'placeholder' => lng('customer.email'),
						'type' => 'email',
						'mandatory' => true,
						'value' => old('admin_email', null, 'installation'),
					],
					'use_admin_email_as_sender' => [
						'label' => lng('install.admin.use_admin_email_as_sender'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => old('use_admin_email_as_sender', '1', 'installation'),
					],
					'sender_email' => [
						'label' => lng('serversettings.adminmail.title'),
						'placeholder' => lng('install.admin.use_autogenerated_email_as_sender'),
						'type' => 'email',
						'value' => old('sender_email', null, 'installation'),
					],
				]
			],
			'step3' => [
				'title' => lng('install.system.title'),
				'description' => lng('install.system.description'),
				'fields' => [
					'distribution' => [
						'label' => lng('admin.configfiles.distribution'),
						'type' => 'select',
						'mandatory' => true,
						'select_var' => $supportedOS,
						'selected' => $guessedDistribution
					],
					'serveripv4' => [
						'label' => lng('install.system.ipv4'),
						'placeholder' => lng('install.system.ipv4'),
						'type' => 'text',
						'value' => old('serveripv4', filter_var($_SERVER['SERVER_ADDR'] ?? "", FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? ($_SERVER['SERVER_ADDR'] ?? "") : "", 'installation'),

					],
					'serveripv6' => [
						'label' => lng('install.system.ipv6'),
						'placeholder' => lng('install.system.ipv6'),
						'type' => 'text',
						'value' => old('serveripv6', filter_var($_SERVER['SERVER_ADDR'] ?? "", FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? ($_SERVER['SERVER_ADDR'] ?? "") : "", 'installation'),
					],
					'servername' => [
						'label' => lng('install.system.servername'),
						'placeholder' => lng('install.system.servername'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('servername', filter_var($_SERVER['SERVER_NAME'] ?? "", FILTER_VALIDATE_IP) ? null : $_SERVER['SERVER_NAME'], 'installation'),
					],
					'use_ssl' => [
						'label' => lng('serversettings.ssl.use_ssl.title'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => old('use_ssl', '1', 'installation'),
					],
					'webserver' => [
						'label' => lng('admin.webserver'),
						'type' => 'select',
						'mandatory' => true,
						'select_var' => ['apache24' => 'Apache 2.4', 'nginx' => 'Nginx'],
						'selected' => old('webserver', $guessedWebserver, 'installation'),
					],
					'webserver_backend' => [
						'label' => lng('install.system.phpbackend'),
						'type' => 'select',
						'mandatory' => true,
						'select_var' => $webserverBackend,
						'selected' => old('webserver_backend', 'php-fpm', 'installation'),
					],
					'httpuser' => [
						'label' => lng('admin.webserver_user'),
						'placeholder' => lng('admin.webserver_user'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('httpuser', $httpuser, 'installation'),
						'advanced' => true,
					],
					'httpgroup' => [
						'label' => lng('admin.webserver_group'),
						'placeholder' => lng('admin.webserver_group'),
						'type' => 'text',
						'mandatory' => true,
						'value' => old('httpgroup', $httpgroup, 'installation'),
						'advanced' => true,
					],
					'activate_newsfeed' => [
						'label' => lng('install.system.activate_newsfeed'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => old('activate_newsfeed', '0', 'installation'),
					],
				]
			],
			'step4' => [
				'title' => lng('install.install.title'),
				'description' => lng('install.install.description'),
				'fields' => [
					'system' => [
						'label' => lng('install.install.runcmd'),
						'type' => 'textarea',
						'value' => (!empty($_SESSION['installation']['ud_str']) ? Froxlor::getInstallDir() . "bin/froxlor-cli froxlor:install -c '" . $_SESSION['installation']['ud_str'] . "'\n" : "") .
							(!empty($_SESSION['installation']['json_params']) ? Froxlor::getInstallDir() . "bin/froxlor-cli froxlor:config-services -a '" . $_SESSION['installation']['json_params'] . "' --yes-to-all" : "something went wrong..."),
						'readonly' => true,
						'rows' => 10,
						'style' => 'min-height:16rem;'
					],
					'manual_config' => [
						'label' => lng('install.install.manual_config'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => old('manual_config', '0', 'installation'),
					],
					'target_servername' => [
						'type' => 'hidden',
						'value' => $_SESSION['installation']['servername'] ?? "",
					],
				]
			]
		]
	]
];
