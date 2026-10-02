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
		'accounts' => [
			'title' => lng('admin.accountsettings'),
			'icon' => 'fa-solid fa-users-gear',
			'fields' => [
				'session_sessiontimeout' => [
					'label' => lng('serversettings.session_timeout'),
					'settinggroup' => 'session',
					'varname' => 'sessiontimeout',
					'type' => 'number',
					'min' => 60,
					'max' => 31536000,
					'default' => 600,
					'save_method' => 'storeSettingField'
				],
				'session_allow_multiple_login' => [
					'label' => lng('serversettings.session_allow_multiple_login'),
					'settinggroup' => 'session',
					'varname' => 'allow_multiple_login',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'login_domain_login' => [
					'label' => lng('serversettings.login_domain_login'),
					'settinggroup' => 'login',
					'varname' => 'domain_login',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'login_maxloginattempts' => [
					'label' => lng('serversettings.maxloginattempts'),
					'settinggroup' => 'login',
					'varname' => 'maxloginattempts',
					'type' => 'number',
					'min' => 1,
					'default' => 3,
					'save_method' => 'storeSettingField'
				],
				'login_deactivatetime' => [
					'label' => lng('serversettings.deactivatetime'),
					'settinggroup' => 'login',
					'varname' => 'deactivatetime',
					'type' => 'number',
					'min' => 0,
					'default' => 900,
					'save_method' => 'storeSettingField'
				],
				'2fa_enabled' => [
					'label' => lng('2fa.2fa_enabled'),
					'settinggroup' => '2fa',
					'varname' => 'enabled',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'panel_password_min_length' => [
					'label' => lng('serversettings.panel_password_min_length'),
					'settinggroup' => 'panel',
					'varname' => 'password_min_length',
					'type' => 'number',
					'min' => 0,
					'default' => 0,
					'save_method' => 'storeSettingField'
				],
				'panel_password_alpha_lower' => [
					'label' => lng('serversettings.panel_password_alpha_lower'),
					'settinggroup' => 'panel',
					'varname' => 'password_alpha_lower',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'panel_password_alpha_upper' => [
					'label' => lng('serversettings.panel_password_alpha_upper'),
					'settinggroup' => 'panel',
					'varname' => 'password_alpha_upper',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'panel_password_numeric' => [
					'label' => lng('serversettings.panel_password_numeric'),
					'settinggroup' => 'panel',
					'varname' => 'password_numeric',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'panel_password_special_char_required' => [
					'label' => lng('serversettings.panel_password_special_char_required'),
					'settinggroup' => 'panel',
					'varname' => 'password_special_char_required',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'panel_password_special_char' => [
					'label' => lng('serversettings.panel_password_special_char'),
					'settinggroup' => 'panel',
					'varname' => 'password_special_char',
					'type' => 'text',
					'default' => '!?<>§$%+#=@',
					'save_method' => 'storeSettingField'
				],
				'panel_password_regex' => [
					'label' => lng('serversettings.panel_password_regex'),
					'settinggroup' => 'panel',
					'varname' => 'password_regex',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_req_limit_per_interval' => [
					'label' => lng('serversettings.req_limit_per_interval'),
					'settinggroup' => 'system',
					'varname' => 'req_limit_per_interval',
					'type' => 'number',
					'min' => 30,
					'default' => 60,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_req_limit_interval' => [
					'label' => lng('serversettings.req_limit_interval'),
					'settinggroup' => 'system',
					'varname' => 'req_limit_interval',
					'type' => 'number',
					'min' => 5,
					'default' => 60,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'customer_accountprefix' => [
					'label' => lng('serversettings.accountprefix'),
					'settinggroup' => 'customer',
					'varname' => 'accountprefix',
					'type' => 'text',
					'default' => '',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkUsername'
					],
					'save_method' => 'storeSettingField'
				],
				'customer_mysqlprefix' => [
					'label' => lng('serversettings.mysqlprefix'),
					'settinggroup' => 'customer',
					'varname' => 'mysqlprefix',
					'type' => 'text',
					'default' => '',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkUsername'
					],
					'save_method' => 'storeSettingField'
				],
				'customer_ftpprefix' => [
					'label' => lng('serversettings.ftpprefix'),
					'settinggroup' => 'customer',
					'varname' => 'ftpprefix',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'customer_ftpatdomain' => [
					'label' => lng('serversettings.ftpdomain'),
					'settinggroup' => 'customer',
					'varname' => 'ftpatdomain',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'panel_allow_preset' => [
					'label' => lng('serversettings.allow_password_reset'),
					'settinggroup' => 'panel',
					'varname' => 'allow_preset',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'dependency' => [
						'fieldname' => 'panel_allow_preset_admin',
						'fielddata' => [
							'settinggroup' => 'panel',
							'varname' => 'allow_preset_admin'
						],
						'onlyif' => 0
					]
				],
				'panel_allow_preset_admin' => [
					'label' => lng('serversettings.allow_password_reset_admin'),
					'settinggroup' => 'panel',
					'varname' => 'allow_preset_admin',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'dependency' => [
						'fieldname' => 'panel_allow_preset',
						'fielddata' => [
							'settinggroup' => 'panel',
							'varname' => 'allow_preset'
						],
						'onlyif' => 1
					]
				],
				'system_exportenabled' => [
					'label' => lng('serversettings.exportenabled'),
					'settinggroup' => 'system',
					'varname' => 'exportenabled',
					'type' => 'checkbox',
					'default' => false,
					'cronmodule' => 'froxlor/export',
					'save_method' => 'storeSettingField'
				],
				'system_createstdsubdom_default' => [
					'label' => lng('serversettings.createstdsubdom_default'),
					'settinggroup' => 'system',
					'varname' => 'createstdsubdom_default',
					'type' => 'select',
					'default' => '1',
					'select_var' => [
						'0' => lng('panel.no'),
						'1' => lng('panel.yes')
					],
					'save_method' => 'storeSettingField'
				],
			]
		]
	]
];
