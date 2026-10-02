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

use Froxlor\Language;
use Froxlor\Settings;
use Froxlor\System\Crypt;

return [
	'admin_add' => [
		'title' => lng('admin.admin_add'),
		'image' => 'fa-solid fa-user-plus',
		'self_overview' => ['section' => 'admins', 'page' => 'admins'],
		'sections' => [
			'section_a' => [
				'title' => lng('admin.accountdata'),
				'fields' => [
					'new_loginname' => [
						'label' => lng('login.username'),
						'type' => 'text',
						'mandatory' => true
					],
					'admin_password' => [
						'label' => lng('login.password'),
						'type' => 'password',
						'mandatory' => true,
						'autocomplete' => 'new-password',
						'next_to' => [
							'admin_password_suggestion' => [
								'next_to_prefix' => lng('customer.generated_pwd') . ':',
								'type' => 'text',
								'visible' => (Settings::Get('panel.password_regex') == ''),
								'value' => Crypt::generatePassword(),
								'readonly' => true
							]
						]
					],
					'def_language' => [
						'label' => lng('login.language'),
						'type' => 'select',
						'select_var' => Language::getLanguages(),
						'selected' => $userinfo['language']

					],
					'gui_access' => [
						'label' => lng('usersettings.gui_access.title'),
						'desc' => lng('usersettings.gui_access.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => 1,
					],
					'api_allowed' => [
						'label' => lng('usersettings.api_allowed.title'),
						'desc' => lng('usersettings.api_allowed.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => Settings::Get('api.enabled') == '1',
						'visible' => Settings::Get('api.enabled') == '1'
					],
				]
			],
			'section_b' => [
				'title' => lng('admin.contactdata'),
				'fields' => [
					'name' => [
						'label' => lng('customer.name'),
						'type' => 'text',
						'mandatory' => true
					],
					'email' => [
						'label' => lng('customer.email'),
						'type' => 'text',
						'mandatory' => true
					],
					'custom_notes' => [
						'label' => lng('usersettings.custom_notes.title'),
						'desc' => lng('usersettings.custom_notes.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12
					],
					'custom_notes_show' => [
						'label' => lng('usersettings.custom_notes.show'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					]
				]
			],
			'section_c' => [
				'title' => lng('admin.servicedata'),
				'fields' => [
					'ipaddress' => [
						'label' => lng('serversettings.ipaddress.title'),
						'type' => 'select',
						'select_var' => $ipaddress
					],
					'change_serversettings' => [
						'label' => lng('admin.change_serversettings'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'customers' => [
						'label' => lng('admin.customers'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'mandatory' => true
					],
					'customers_see_all' => [
						'label' => lng('admin.customers_see_all'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'domains' => [
						'label' => lng('admin.domains'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'mandatory' => true
					],
					'caneditphpsettings' => [
						'label' => lng('admin.caneditphpsettings'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'diskspace' => [
						'label' => lng('customer.diskspace') . ' (' . lng('customer.mib') . ')',
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 6,
						'mandatory' => true
					],
					'traffic' => [
						'label' => lng('customer.traffic') . ' (' . lng('customer.gib') . ')',
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 4,
						'mandatory' => true
					],
					'subdomains' => [
						'label' => lng('customer.subdomains'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'mandatory' => true
					],
					'emails' => [
						'label' => lng('customer.emails'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'mandatory' => true
					],
					'email_accounts' => [
						'label' => lng('customer.accounts'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'mandatory' => true
					],
					'email_forwarders' => [
						'label' => lng('customer.forwarders'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'mandatory' => true
					],
					'email_quota' => [
						'label' => lng('customer.email_quota') . ' (' . lng('customer.mib') . ')',
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'visible' => Settings::Get('system.mail_quota_enabled') == '1',
						'mandatory' => true
					],
					'ftps' => [
						'label' => lng('customer.ftps'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9
					],
					'mysqls' => [
						'label' => lng('customer.mysqls'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => 0,
						'maxlength' => 9,
						'mandatory' => true
					]
				]
			]
		]
	]
];
