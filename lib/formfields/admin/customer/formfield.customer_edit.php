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
	'customer_edit' => [
		'title' => lng('admin.customer_edit'),
		'image' => 'fa-solid fa-user-pen',
		'self_overview' => ['section' => 'customers', 'page' => 'customers'],
		'id' => 'customer_edit',
		'sections' => [
			'section_a' => [
				'title' => lng('admin.accountdata'),
				'fields' => [
					'loginname' => [
						'label' => lng('login.username'),
						'type' => 'label',
						'value' => $result['loginname']
					],
					'documentroot' => [
						'label' => lng('customer.documentroot'),
						'type' => 'label',
						'value' => $result['documentroot']
					],
					'createstdsubdomain' => [
						'label' => lng('admin.stdsubdomain_add') . '?',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => (bool)$result['standardsubdomain']
					],
					'deactivated' => [
						'label' => lng('admin.deactivated_user'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['deactivated']
					],
					'new_customer_password' => [
						'label' => lng('login.password') . '&nbsp;(' . lng('panel.emptyfornochanges') . ')',
						'type' => 'password',
						'autocomplete' => 'new-password',
						'next_to' => [
							'new_customer_password_suggestion' => [
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
						'selected' => $result['def_language']
					],
					'gui_access' => [
						'label' => lng('usersettings.gui_access.title'),
						'desc' => lng('usersettings.gui_access.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['gui_access'],
					],
					'api_allowed' => [
						'label' => lng('usersettings.api_allowed.title'),
						'desc' => lng('usersettings.api_allowed.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['api_allowed'],
						'visible' => Settings::Get('api.enabled') == '1'
					],
					'shell_allowed' => [
						'label' => lng('usersettings.shell_allowed.title'),
						'desc' => lng('usersettings.shell_allowed.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['shell_allowed'],
						'visible' => Settings::Get('system.allow_customer_shell') == '1',
					],
				]
			],
			'section_b' => [
				'title' => lng('admin.contactdata'),
				'fields' => [
					'gender' => [
						'label' => lng('gender.title'),
						'type' => 'select',
						'select_var' => [
							0 => lng('gender.undef'),
							1 => lng('gender.male'),
							2 => lng('gender.female')
						],
						'selected' => $result['gender']
					],
					'firstname' => [
						'label' => lng('customer.firstname'),
						'desc' => lng('customer.nameorcompany_desc'),
						'type' => 'text',
						'mandatory' => true,
						'value' => $result['firstname']
					],
					'name' => [
						'label' => lng('customer.lastname'),
						'desc' => lng('customer.nameorcompany_desc'),
						'type' => 'text',
						'mandatory' => true,
						'value' => $result['name']
					],
					'company' => [
						'label' => lng('customer.company'),
						'desc' => lng('customer.nameorcompany_desc'),
						'type' => 'text',
						'mandatory' => true,
						'value' => $result['company']
					],
					'street' => [
						'label' => lng('customer.street'),
						'type' => 'text',
						'value' => $result['street']
					],
					'zipcode' => [
						'label' => lng('customer.zipcode') . ' / ' . lng('customer.city'),
						'type' => 'text',
						'value' => $result['zipcode'],
						'next_to' => [
							'city' => [
								'next_to_prefix' => ' / ',
								'type' => 'text',
								'value' => $result['city']
							]
						]
					],
					'phone' => [
						'label' => lng('customer.phone'),
						'type' => 'text',
						'value' => $result['phone']
					],
					'fax' => [
						'label' => lng('customer.fax'),
						'type' => 'text',
						'value' => $result['fax']
					],
					'email' => [
						'label' => lng('customer.email'),
						'type' => 'text',
						'mandatory' => true,
						'value' => $result['email']
					],
					'customernumber' => [
						'label' => lng('customer.customernumber'),
						'type' => 'text',
						'value' => $result['customernumber']
					],
					'custom_notes' => [
						'style' => 'align-top',
						'label' => lng('usersettings.custom_notes.title'),
						'desc' => lng('usersettings.custom_notes.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12,
						'value' => $result['custom_notes']
					],
					'custom_notes_show' => [
						'label' => lng('usersettings.custom_notes.show'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['custom_notes_show']
					]
				]
			],
			'section_cpre' => [
				'visible' => !empty($hosting_plans),
				'title' => lng('admin.plans.use_plan'),
				'fields' => [
					'use_plan' => [
						'label' => lng('admin.plans.use_plan'),
						'type' => 'select',
						'select_var' => $hosting_plans
					]
				]
			],
			'section_c' => [
				'title' => lng('admin.servicedata'),
				'fields' => [
					'diskspace' => [
						'label' => lng('customer.diskspace') . ' (' . lng('customer.mib') . ')',
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['diskspace']) ? '0' : $result['diskspace'],
						'maxlength' => 16,
						'mandatory' => true
					],
					'traffic' => [
						'label' => lng('customer.traffic') . ' (' . lng('customer.gib') . ')',
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['traffic']) ? '0' : $result['traffic'],
						'maxlength' => 14,
						'mandatory' => true
					],
					'subdomains' => [
						'label' => lng('customer.subdomains'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['subdomains']) ? '0' : $result['subdomains'],
						'maxlength' => 9,
						'mandatory' => true
					],
					'emails' => [
						'label' => lng('customer.emails'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['emails']) ? '0' : $result['emails'],
						'maxlength' => 9,
						'mandatory' => true
					],
					'email_accounts' => [
						'label' => lng('customer.accounts'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['email_accounts']) ? '0' : $result['email_accounts'],
						'maxlength' => 9,
						'mandatory' => true
					],
					'email_forwarders' => [
						'label' => lng('customer.forwarders'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['email_forwarders']) ? '0' : $result['email_forwarders'],
						'maxlength' => 9,
						'mandatory' => true
					],
					'email_quota' => [
						'label' => lng('customer.email_quota') . ' (' . lng('customer.mib') . ')',
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['email_quota']) ? '0' : $result['email_quota'],
						'maxlength' => 9,
						'visible' => Settings::Get('system.mail_quota_enabled') == '1',
						'mandatory' => true
					],
					'email_imap' => [
						'label' => lng('customer.email_imap'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['imap'],
						'mandatory' => true
					],
					'email_pop3' => [
						'label' => lng('customer.email_pop3'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['pop3'],
						'mandatory' => true
					],
					'ftps' => [
						'label' => lng('customer.ftps'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['ftps']) ? '0' : $result['ftps'],
						'maxlength' => 9,
						'mandatory' => true
					],
					'mysqls' => [
						'label' => lng('customer.mysqls'),
						'desc' => lng('panel.use_checkbox_for_unlimited'),
						'type' => 'textul',
						'value' => empty($result['mysqls']) ? '0' : $result['mysqls'],
						'maxlength' => 9,
						'mandatory' => true
					],
					'allowed_mysqlserver' => [
						'visible' => count($mysql_servers) > 1,
						'label' => lng('customer.mysqlserver'),
						'type' => 'checkbox',
						'values' => $mysql_servers,
						'value' => isset($result['allowed_mysqlserver']) && !empty($result['allowed_mysqlserver']) ? json_decode($result['allowed_mysqlserver'], JSON_OBJECT_AS_ARRAY) : [],
						'is_array' => 1
					],
					'phpenabled' => [
						'label' => lng('admin.phpenabled') . '?',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['phpenabled']
					],
					'allowed_phpconfigs' => [
						'visible' => (((int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1)),
						'label' => lng('admin.phpsettings.title'),
						'type' => 'checkbox',
						'values' => $phpconfigs,
						'value' => isset($result['allowed_phpconfigs']) && !empty($result['allowed_phpconfigs']) ? json_decode($result['allowed_phpconfigs'], JSON_OBJECT_AS_ARRAY) : [],
						'is_array' => 1
					],
					'perlenabled' => [
						'label' => lng('admin.perlenabled') . '?',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['perlenabled']
					],
					'dnsenabled' => [
						'label' => lng('admin.dnsenabled') . '?',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['dnsenabled'],
						'visible' => Settings::Get('system.dnsenabled') == '1'
					],
					'logviewenabled' => [
						'label' => lng('admin.logviewenabled') . '?',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['logviewenabled']
					],
				]
			],
			'section_d' => [
				'title' => lng('admin.movetoadmin'),
				'visible' => count($admin_select) > 0,
				'fields' => [
					'move_to_admin' => [
						'label' => lng('admin.movecustomertoadmin'),
						'type' => 'select',
						'select_var' => $admin_select
					]
				]
			]
		]
	]
];
