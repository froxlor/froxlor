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
		'nameserver' => [
			'title' => lng('admin.nameserversettings'),
			'icon' => 'fa-solid fa-globe',
			'fields' => [
				'system_bind_enable' => [
					'label' => lng('serversettings.bindenable'),
					'settinggroup' => 'system',
					'varname' => 'bind_enable',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'overview_option' => true,
					'requires_reconf' => ['dns']
				],
				'system_dnsenabled' => [
					'label' => lng('serversettings.dnseditorenable'),
					'settinggroup' => 'system',
					'varname' => 'dnsenabled',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'system_dns_server' => [
					'label' => lng('serversettings.dns_server'),
					'settinggroup' => 'system',
					'varname' => 'dns_server',
					'type' => 'select',
					'default' => 'Bind',
					'select_var' => [
						'Bind' => 'Bind9',
						'PowerDNS' => 'PowerDNS'
					],
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['dns']
				],
				'system_bindconf_directory' => [
					'label' => lng('serversettings.bindconf_directory'),
					'settinggroup' => 'system',
					'varname' => 'bindconf_directory',
					'type' => 'text',
					'string_type' => 'dir',
					'default' => '/etc/bind/',
					'save_method' => 'storeSettingField',
					'visible' => Settings::Get('system.dns_server') == 'Bind',
					'requires_reconf' => ['dns:bind']
				],
				'system_bindreload_command' => [
					'label' => lng('serversettings.bindreload_command'),
					'settinggroup' => 'system',
					'varname' => 'bindreload_command',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => '/etc/init.d/bind9 reload',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_nameservers' => [
					'label' => lng('serversettings.nameservers'),
					'settinggroup' => 'system',
					'varname' => 'nameservers',
					'type' => 'text',
					'string_regexp' => '/^(([a-z0-9\-\._]+, ?)*[a-z0-9\-\._]+)?$/i',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingFieldInsertBindTask'
				],
				'system_mxservers' => [
					'label' => lng('serversettings.mxservers'),
					'settinggroup' => 'system',
					'varname' => 'mxservers',
					'type' => 'text',
					'string_regexp' => '/^(([0-9]+ [a-z0-9\-\._]+, ?)*[0-9]+ [a-z0-9\-\._]+)?$/i',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'system_axfrservers' => [
					'label' => lng('serversettings.axfrservers'),
					'settinggroup' => 'system',
					'varname' => 'axfrservers',
					'type' => 'text',
					'string_type' => 'validate_ip_incl_private',
					'string_delimiter' => ',',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_powerdns_mode' => [
					'label' => lng('serversettings.powerdns_mode'),
					'settinggroup' => 'system',
					'varname' => 'powerdns_mode',
					'type' => 'select',
					'default' => 'Native',
					'select_var' => [
						'Native' => 'Native',
						'Master' => 'Master'
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'visible' => Settings::Get('system.dns_server') == 'PowerDNS',
				],
				'system_dns_createmailentry' => [
					'label' => lng('serversettings.mail_also_with_mxservers'),
					'settinggroup' => 'system',
					'varname' => 'dns_createmailentry',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'system_dns_createcaaentry' => [
					'label' => lng('serversettings.caa_entry'),
					'settinggroup' => 'system',
					'varname' => 'dns_createcaaentry',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'caa_caa_entry' => [
					'label' => lng('serversettings.caa_entry_custom'),
					'settinggroup' => 'caa',
					'varname' => 'caa_entry',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_defaultttl' => [
					'label' => lng('serversettings.defaultttl'),
					'settinggroup' => 'system',
					'varname' => 'defaultttl',
					'type' => 'number',
					'default' => 604800, /* 1 week */
					'min' => 3600, /* 1 hour */
					'max' => 2147483647, /* integer max */
					'save_method' => 'storeSettingField'
				],
				'system_soaemail' => [
					'label' => lng('serversettings.soaemail'),
					'settinggroup' => 'system',
					'varname' => 'soaemail',
					'type' => 'email',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				]
			]
		]
	]
];
