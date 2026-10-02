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
	'groups' => [
		'phpfpm' => [
			'title' => lng('admin.phpfpm_settings'),
			'icon' => 'fa-brands fa-php',
			'fields' => [
				'phpfpm_enabled' => [
					'label' => lng('serversettings.phpfpm'),
					'settinggroup' => 'phpfpm',
					'varname' => 'enabled',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkFcgidPhpFpm'
					],
					'overview_option' => true,
					'requires_reconf' => ['http', 'system:php-fpm']
				],
				'phpfpm_defaultini' => [
					'label' => lng('serversettings.mod_fcgid.defaultini'),
					'settinggroup' => 'phpfpm',
					'varname' => 'defaultini',
					'type' => 'select',
					'default' => '1',
					'option_options_method' => [
						'\\Froxlor\\Http\\PhpConfig',
						'getPhpConfigs'
					],
					'save_method' => 'storeSettingField'
				],
				'phpfpm_aliasconfigdir' => [
					'label' => lng('serversettings.phpfpm_settings.aliasconfigdir'),
					'settinggroup' => 'phpfpm',
					'varname' => 'aliasconfigdir',
					'type' => 'text',
					'string_type' => 'confdir',
					'default' => '/var/www/php-fpm/',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'phpfpm_tmpdir' => [
					'label' => lng('serversettings.mod_fcgid.tmpdir'),
					'settinggroup' => 'phpfpm',
					'varname' => 'tmpdir',
					'type' => 'text',
					'string_type' => 'dir',
					'default' => '/var/customers/tmp/',
					'save_method' => 'storeSettingField'
				],
				'phpfpm_peardir' => [
					'label' => lng('serversettings.mod_fcgid.peardir'),
					'settinggroup' => 'phpfpm',
					'varname' => 'peardir',
					'type' => 'text',
					'string_type' => 'dir',
					'string_delimiter' => ':',
					'string_emptyallowed' => true,
					'default' => '/usr/share/php/:/usr/share/php5/',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'phpfpm_envpath' => [
					'label' => lng('serversettings.phpfpm_settings.envpath'),
					'settinggroup' => 'phpfpm',
					'varname' => 'envpath',
					'type' => 'text',
					'string_type' => 'dir',
					'string_delimiter' => ':',
					'string_emptyallowed' => true,
					'default' => '/usr/local/bin:/usr/bin:/bin',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'phpfpm_fastcgi_ipcdir' => [
					'label' => lng('serversettings.phpfpm_settings.ipcdir'),
					'settinggroup' => 'phpfpm',
					'varname' => 'fastcgi_ipcdir',
					'type' => 'text',
					'string_type' => 'dir',
					'default' => '/var/lib/apache2/fastcgi/',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'phpfpm_use_mod_proxy' => [
					'label' => lng('phpfpm.use_mod_proxy'),
					'settinggroup' => 'phpfpm',
					'varname' => 'use_mod_proxy',
					'type' => 'checkbox',
					'default' => true,
					'visible' => Settings::Get('system.apache24'),
					'save_method' => 'storeSettingField'
				],
				'phpfpm_ini_flags' => [
					'label' => lng('phpfpm.ini_flags'),
					'settinggroup' => 'phpfpm',
					'varname' => 'ini_flags',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'phpfpm_ini_values' => [
					'label' => lng('phpfpm.ini_values'),
					'settinggroup' => 'phpfpm',
					'varname' => 'ini_values',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'phpfpm_ini_admin_flags' => [
					'label' => lng('phpfpm.ini_admin_flags'),
					'settinggroup' => 'phpfpm',
					'varname' => 'ini_admin_flags',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'phpfpm_ini_admin_values' => [
					'label' => lng('phpfpm.ini_admin_values'),
					'settinggroup' => 'phpfpm',
					'varname' => 'ini_admin_values',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				]
			]
		]
	]
];
