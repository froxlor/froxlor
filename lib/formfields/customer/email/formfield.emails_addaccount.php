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
use Froxlor\System\Crypt;

return [
	'emails_addaccount' => [
		'title' => lng('emails.account_add'),
		'image' => 'fa-solid fa-plus',
		'sections' => [
			'section_a' => [
				'title' => lng('emails.account_add'),
				'fields' => [
					'emailaddr' => [
						'label' => lng('emails.emailaddress'),
						'type' => 'label',
						'value' => $result['email_full']
					],
					'email_password' => [
						'label' => lng('login.password'),
						'type' => 'password',
						'autocomplete' => 'new-password',
						'mandatory' => true,
						'next_to' => [
							'email_password_suggestion' => [
								'next_to_prefix' => lng('customer.generated_pwd') . ':',
								'type' => 'text',
								'visible' => (Settings::Get('panel.password_regex') == ''),
								'value' => Crypt::generatePassword(),
								'readonly' => true
							]
						]
					],
					'email_quota' => [
						'visible' => Settings::Get('system.mail_quota_enabled') == '1',
						'label' => lng('emails.quota'),
						'desc' => "MiB",
						'type' => 'number',
						'value' => $quota
					],
					'alternative_email' => [
						'visible' => Settings::Get('panel.sendalternativemail') == '1',
						'label' => lng('emails.alternative_emailaddress'),
						'type' => 'text'
					]
				]
			]
		]
	]
];
