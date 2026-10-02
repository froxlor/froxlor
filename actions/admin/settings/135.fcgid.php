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

return [
	'groups' => [
		'fcgid' => [
			'title' => lng('admin.fcgid_settings'),
			'icon' => 'fa-brands fa-php',
			'websrv_avail' => [
				'apache2',
			],
			'fields' => [
				'system_mod_fcgid' => [
					'label' => lng('serversettings.mod_fcgid'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkFcgidPhpFpm'
					],
					'overview_option' => true,
					'requires_reconf' => ['http', 'system:fcgid']
				],
				'system_mod_fcgid_configdir' => [
					'label' => lng('serversettings.mod_fcgid.configdir'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_configdir',
					'type' => 'text',
					'string_type' => 'confdir',
					'default' => '/var/www/php-fcgi-scripts/',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkPathConflicts'
					],
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['system:fcgid']
				],
				'system_mod_fcgid_tmpdir' => [
					'label' => lng('serversettings.mod_fcgid.tmpdir'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_tmpdir',
					'type' => 'text',
					'string_type' => 'dir',
					'default' => '/var/customers/tmp/',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http']
				],
				'system_mod_fcgid_peardir' => [
					'label' => lng('serversettings.mod_fcgid.peardir'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_peardir',
					'type' => 'text',
					'string_type' => 'dir',
					'string_delimiter' => ':',
					'string_emptyallowed' => true,
					'default' => '/usr/share/php/:/usr/share/php5/',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_mod_fcgid_wrapper' => [
					'label' => lng('serversettings.mod_fcgid.wrapper'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_wrapper',
					'type' => 'select',
					'select_var' => [
						0 => 'ScriptAlias',
						1 => 'FcgidWrapper'
					],
					'default' => 1,
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2'
					],
					'advanced_mode' => true
				],
				'system_mod_fcgid_starter' => [
					'label' => lng('serversettings.mod_fcgid.starter'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_starter',
					'type' => 'number',
					'min' => 0,
					'default' => 0,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_mod_fcgid_maxrequests' => [
					'label' => lng('serversettings.mod_fcgid.maxrequests'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_maxrequests',
					'type' => 'number',
					'default' => 250,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_mod_fcgid_defaultini' => [
					'label' => lng('serversettings.mod_fcgid.defaultini'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_defaultini',
					'type' => 'select',
					'default' => '1',
					'option_options_method' => [
						'\\Froxlor\\Http\\PhpConfig',
						'getPhpConfigs'
					],
					'save_method' => 'storeSettingField'
				],
				'system_mod_fcgid_idle_timeout' => [
					'label' => lng('serversettings.mod_fcgid.idle_timeout'),
					'settinggroup' => 'system',
					'varname' => 'mod_fcgid_idle_timeout',
					'type' => 'number',
					'default' => 30,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				]
			]
		]
	]
];
