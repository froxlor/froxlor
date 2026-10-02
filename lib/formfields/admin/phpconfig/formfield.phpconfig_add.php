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

use Froxlor\Settings;

return [
	'phpconfig_add' => [
		'title' => lng('admin.phpsettings.addsettings'),
		'image' => 'fa-solid fa-plus',
		'self_overview' => ['section' => 'phpsettings', 'page' => 'overview'],
		'sections' => [
			'section_a' => [
				'title' => lng('admin.phpsettings.addsettings'),
				'fields' => [
					'description' => [
						'label' => lng('admin.phpsettings.description'),
						'type' => 'text',
						'maxlength' => 50,
						'mandatory' => true
					],
					'binary' => [
						'visible' => Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.phpsettings.binary'),
						'type' => 'text',
						'maxlength' => 255,
						'value' => '/usr/bin/php-cgi',
						'required_otp' => true
					],
					'fpmconfig' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('admin.phpsettings.fpmdesc'),
						'type' => 'select',
						'select_var' => $fpmconfigs,
						'selected' => 1
					],
					'file_extensions' => [
						'visible' => Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.phpsettings.file_extensions'),
						'desc' => lng('admin.phpsettings.file_extensions_note'),
						'type' => 'text',
						'maxlength' => 255,
						'value' => 'php',
						'required_otp' => true
					],
					'mod_fcgid_starter' => [
						'visible' => Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.mod_fcgid_starter.title'),
						'type' => 'number'
					],
					'mod_fcgid_maxrequests' => [
						'visible' => Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.mod_fcgid_maxrequests.title'),
						'type' => 'number'
					],
					'mod_fcgid_umask' => [
						'visible' => Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.mod_fcgid_umask.title'),
						'type' => 'text',
						'maxlength' => 3,
						'value' => '022'
					],
					'phpfpm_enable_slowlog' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('admin.phpsettings.enable_slowlog'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'phpfpm_reqtermtimeout' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('admin.phpsettings.request_terminate_timeout'),
						'type' => 'text',
						'maxlength' => 10,
						'value' => '60s'
					],
					'phpfpm_reqslowtimeout' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('admin.phpsettings.request_slowlog_timeout'),
						'type' => 'text',
						'maxlength' => 10,
						'value' => '5s'
					],
					'pass_authorizationheader' => [
						'visible' => Settings::Get('system.webserver') == "apache2",
						'label' => lng('admin.phpsettings.pass_authorizationheader'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'override_fpmconfig' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.override_fpmconfig'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'pm' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.pm'),
						'desc' => lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'select',
						'select_var' => [
							'static' => 'static',
							'dynamic' => 'dynamic',
							'ondemand' => 'ondemand'
						]
					],
					'max_children' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.max_children.title'),
						'desc' => lng('serversettings.phpfpm_settings.max_children.description') . lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'number',
						'value' => 1
					],
					'start_servers' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.start_servers.title'),
						'desc' => lng('serversettings.phpfpm_settings.start_servers.description') . lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'number',
						'value' => 20
					],
					'min_spare_servers' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.min_spare_servers.title'),
						'desc' => lng('serversettings.phpfpm_settings.min_spare_servers.description') . lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'number',
						'value' => 5
					],
					'max_spare_servers' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.max_spare_servers.title'),
						'desc' => lng('serversettings.phpfpm_settings.max_spare_servers.description') . lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'number',
						'value' => 35
					],
					'max_requests' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.max_requests.title'),
						'desc' => lng('serversettings.phpfpm_settings.max_requests.description') . lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'number',
						'value' => 0
					],
					'idle_timeout' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.idle_timeout.title'),
						'desc' => lng('serversettings.phpfpm_settings.idle_timeout.description') . lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'number',
						'value' => 10
					],
					'limit_extensions' => [
						'visible' => Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('serversettings.phpfpm_settings.limit_extensions.title'),
						'desc' => lng('serversettings.phpfpm_settings.limit_extensions.description') . lng('serversettings.phpfpm_settings.override_fpmconfig_addinfo'),
						'type' => 'text',
						'value' => '.php'
					],
					'phpsettings' => [
						'label' => lng('admin.phpsettings.phpinisettings'),
						'type' => 'textarea',
						'cols' => 80,
						'rows' => 20,
						'value' => $result['phpsettings'],
						'mandatory' => true,
						'required_otp' => true
					],
					'allow_all_customers' => [
						'label' => lng('serversettings.phpfpm_settings.allow_all_customers.title'),
						'desc' => lng('serversettings.phpfpm_settings.allow_all_customers.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					]
				]
			]
		]
	],
	'phpconfig_replacers' => [
		'replacers' => [
			[
				'var' => 'PEAR_DIR',
				'description' => lng('admin.phpconfig.pear_dir')
			],
			[
				'var' => 'OPEN_BASEDIR_C',
				'description' => lng('admin.phpconfig.open_basedir_c')
			],
			[
				'var' => 'OPEN_BASEDIR',
				'description' => lng('admin.phpconfig.open_basedir')
			],
			[
				'var' => 'OPEN_BASEDIR_GLOBAL',
				'description' => lng('admin.phpconfig.open_basedir_global')
			],
			[
				'var' => 'TMP_DIR',
				'description' => lng('admin.phpconfig.tmp_dir')
			],
			[
				'var' => 'CUSTOMER_EMAIL',
				'description' => lng('admin.phpconfig.customer_email')
			],
			[
				'var' => 'ADMIN_EMAIL',
				'description' => lng('admin.phpconfig.admin_email')
			],
			[
				'var' => 'DOMAIN',
				'description' => lng('admin.phpconfig.domain')
			],
			[
				'var' => 'CUSTOMER',
				'description' => lng('admin.phpconfig.customer')
			],
			[
				'var' => 'ADMIN',
				'description' => lng('admin.phpconfig.admin')
			],
			[
				'var' => 'DOCUMENT_ROOT',
				'description' => lng('admin.phpconfig.docroot')
			],
			[
				'var' => 'CUSTOMER_HOMEDIR',
				'description' => lng('admin.phpconfig.homedir')
			]
		]
	]
];
