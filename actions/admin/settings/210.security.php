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
		'security' => [
			'title' => lng('admin.security_settings'),
			'icon' => 'fa-solid fa-user-lock',
			'fields' => [
				'panel_unix_names' => [
					'label' => lng('serversettings.unix_names'),
					'settinggroup' => 'panel',
					'varname' => 'unix_names',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_mailpwcleartext' => [
					'label' => lng('serversettings.mailpwcleartext'),
					'settinggroup' => 'system',
					'varname' => 'mailpwcleartext',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'system_passwordcryptfunc' => [
					'label' => lng('serversettings.passwordcryptfunc'),
					'settinggroup' => 'system',
					'varname' => 'passwordcryptfunc',
					'type' => 'select',
					'default' => PASSWORD_DEFAULT,
					'option_options_method' => [
						'\\Froxlor\\System\\Crypt',
						'getAvailablePasswordHashes'
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'system_allow_error_report_admin' => [
					'label' => lng('serversettings.allow_error_report_admin'),
					'settinggroup' => 'system',
					'varname' => 'allow_error_report_admin',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_allow_error_report_customer' => [
					'label' => lng('serversettings.allow_error_report_customer'),
					'settinggroup' => 'system',
					'varname' => 'allow_error_report_customer',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_allow_customer_shell' => [
					'label' => lng('serversettings.allow_allow_customer_shell'),
					'settinggroup' => 'system',
					'varname' => 'allow_customer_shell',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'system_available_shells' => [
					'label' => lng('serversettings.available_shells'),
					'settinggroup' => 'system',
					'varname' => 'available_shells',
					'type' => 'text',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'system_froxlorusergroup' => [
					'label' => lng('serversettings.froxlorusergroup'),
					'settinggroup' => 'system',
					'varname' => 'froxlorusergroup',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkLocalGroup'
					],
					'visible' => Settings::Get('system.nssextrausers'),
					'advanced_mode' => true,
					'required_otp' => true
				],
			]
		]
	]
];
