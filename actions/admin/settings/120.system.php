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
		'system' => [
			'title' => lng('admin.systemsettings'),
			'icon' => 'fa-solid fa-gears',
			'fields' => [
				'system_documentroot_prefix' => [
					'label' => lng('serversettings.documentroot_prefix'),
					'settinggroup' => 'system',
					'varname' => 'documentroot_prefix',
					'type' => 'text',
					'string_type' => 'dir',
					'default' => '/var/customers/webs/',
					'save_method' => 'storeSettingField',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkPathConflicts'
					],
					'requires_reconf' => ['http']
				],
				'system_documentroot_use_default_value' => [
					'label' => lng('serversettings.documentroot_use_default_value'),
					'settinggroup' => 'system',
					'varname' => 'documentroot_use_default_value',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'system_ipaddress' => [
					'label' => lng('serversettings.ipaddress'),
					'settinggroup' => 'system',
					'varname' => 'ipaddress',
					'type' => 'select',
					'option_options_method' => [
						'\\Froxlor\\Domain\\IpAddr',
						'getIpAddresses'
					],
					'default' => '',
					'save_method' => 'storeSettingIpAddress'
				],
				'system_defaultip' => [
					'label' => lng('serversettings.defaultip'),
					'settinggroup' => 'system',
					'varname' => 'defaultip',
					'type' => 'select',
					'select_mode' => 'multiple',
					'option_options_method' => [
						'\\Froxlor\\Domain\\IpAddr',
						'getIpPortCombinations'
					],
					'default' => '',
					'save_method' => 'storeSettingDefaultIp'
				],
				'system_defaultsslip' => [
					'label' => lng('serversettings.defaultsslip'),
					'settinggroup' => 'system',
					'varname' => 'defaultsslip',
					'type' => 'select',
					'select_mode' => 'multiple',
					'option_options_method' => [
						'\\Froxlor\\Domain\\IpAddr',
						'getSslIpPortCombinations'
					],
					'default' => '',
					'save_method' => 'storeSettingDefaultSslIp'
				],
				'system_hostname' => [
					'label' => lng('serversettings.hostname'),
					'settinggroup' => 'system',
					'varname' => 'hostname',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingHostname',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkHostname'
					]
				],
				'api_enabled' => [
					'label' => lng('serversettings.enable_api'),
					'settinggroup' => 'api',
					'varname' => 'enabled',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'api_customer_default' => [
					'label' => lng('serversettings.api_customer_default'),
					'settinggroup' => 'api',
					'varname' => 'customer_default',
					'type' => 'select',
					'default' => 1,
					'select_var' => [
						1 => lng('panel.yes'),
						0 => lng('panel.no')
					],
					'save_method' => 'storeSettingField'
				],
				'system_update_channel' => [
					'label' => lng('serversettings.update_channel'),
					'settinggroup' => 'system',
					'varname' => 'update_channel',
					'type' => 'select',
					'default' => 'stable',
					'select_var' => [
						'stable' => lng('serversettings.uc_stable'),
						'testing' => lng('serversettings.uc_testing'),
						'nightly' => lng('serversettings.uc_nightly')
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_validate_domain' => [
					'label' => lng('serversettings.validate_domain'),
					'settinggroup' => 'system',
					'varname' => 'validate_domain',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'system_stdsubdomain' => [
					'label' => lng('serversettings.stdsubdomainhost'),
					'settinggroup' => 'system',
					'varname' => 'stdsubdomain',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingHostname'
				],
				'system_mysql_access_host' => [
					'label' => lng('serversettings.mysql_access_host'),
					'settinggroup' => 'system',
					'varname' => 'mysql_access_host',
					'type' => 'text',
					'default' => '127.0.0.1,localhost',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkMysqlAccessHost'
					],
					'save_method' => 'storeSettingMysqlAccessHost'
				],
				'system_nssextrausers' => [
					'label' => lng('serversettings.nssextrausers'),
					'settinggroup' => 'system',
					'varname' => 'nssextrausers',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'system_store_index_file_subs' => [
					'label' => lng('serversettings.system_store_index_file_subs'),
					'settinggroup' => 'system',
					'varname' => 'store_index_file_subs',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'system_report_enable' => [
					'label' => lng('serversettings.report.report'),
					'settinggroup' => 'system',
					'varname' => 'report_enable',
					'type' => 'checkbox',
					'default' => true,
					'cronmodule' => 'froxlor/reports',
					'save_method' => 'storeSettingField'
				],
				'system_report_webmax' => [
					'label' => lng('serversettings.report.webmax'),
					'settinggroup' => 'system',
					'varname' => 'report_webmax',
					'type' => 'number',
					'min' => 0,
					'max' => 150,
					'default' => 90,
					'save_method' => 'storeSettingField'
				],
				'system_report_trafficmax' => [
					'label' => lng('serversettings.report.trafficmax'),
					'settinggroup' => 'system',
					'varname' => 'report_trafficmax',
					'type' => 'number',
					'min' => 0,
					'max' => 150,
					'default' => 90,
					'save_method' => 'storeSettingField'
				],
				'system_report_web_bccadmin' => [
					'label' => lng('serversettings.report.report_web_bccadmin'),
					'settinggroup' => 'system',
					'varname' => 'report_web_bccadmin',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'system_mail_use_smtp' => [
					'label' => lng('serversettings.mail_use_smtp'),
					'settinggroup' => 'system',
					'varname' => 'mail_use_smtp',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'system_mail_smtp_host' => [
					'label' => lng('serversettings.mail_smtp_host'),
					'settinggroup' => 'system',
					'varname' => 'mail_smtp_host',
					'type' => 'text',
					'default' => 'localhost',
					'save_method' => 'storeSettingField'
				],
				'system_mail_smtp_port' => [
					'label' => lng('serversettings.mail_smtp_port'),
					'settinggroup' => 'system',
					'varname' => 'mail_smtp_port',
					'type' => 'number',
					'min' => 1,
					'max' => 65535,
					'default' => 25,
					'save_method' => 'storeSettingField'
				],
				'system_mail_smtp_usetls' => [
					'label' => lng('serversettings.mail_smtp_usetls'),
					'settinggroup' => 'system',
					'varname' => 'mail_smtp_usetls',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'system_mail_smtp_auth' => [
					'label' => lng('serversettings.mail_smtp_auth'),
					'settinggroup' => 'system',
					'varname' => 'mail_smtp_auth',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'system_mail_smtp_user' => [
					'label' => lng('serversettings.mail_smtp_user'),
					'settinggroup' => 'system',
					'varname' => 'mail_smtp_user',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'autocomplete' => 'off'
				],
				'system_mail_smtp_passwd' => [
					'label' => lng('serversettings.mail_smtp_passwd'),
					'settinggroup' => 'system',
					'varname' => 'mail_smtp_passwd',
					'type' => 'password',
					'default' => '',
					'save_method' => 'storeSettingField',
					'autocomplete' => 'new-password'
				],
				'system_apply_specialsettings_default' => [
					'label' => lng('serversettings.apply_specialsettings_default'),
					'settinggroup' => 'system',
					'varname' => 'apply_specialsettings_default',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_apply_phpconfigs_default' => [
					'label' => lng('serversettings.apply_phpconfigs_default'),
					'settinggroup' => 'system',
					'varname' => 'apply_phpconfigs_default',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_domaindefaultalias' => [
					'label' => lng('admin.domaindefaultalias'),
					'settinggroup' => 'system',
					'varname' => 'domaindefaultalias',
					'type' => 'select',
					'default' => '0',
					'select_var' => [
						'0' => lng('domains.serveraliasoption_wildcard'),
						'1' => lng('domains.serveraliasoption_www'),
						'2' => lng('domains.serveraliasoption_none')
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_hide_incompatible_settings' => [
					'label' => lng('serversettings.hide_incompatible_settings'),
					'settinggroup' => 'system',
					'varname' => 'hide_incompatible_settings',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
			]
		]
	]
];
