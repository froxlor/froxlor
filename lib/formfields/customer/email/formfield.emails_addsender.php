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
	'emails_addsender' => [
		'title' => lng('emails.sender_add'),
		'image' => 'fa-solid fa-plus',
		'sections' => [
			'section_a' => [
				'title' => lng('emails.sender_add'),
				'fields' => [
					'emailaddr' => [
						'label' => lng('emails.account'),
						'type' => 'label',
						'value' => $result['email_full']
					],
					'allowed_sender' => [
						'label' => lng('emails.foreign_sender').'<span class="text-danger">*</span>',
						'type' => 'text',
						'string_regex' => '/^[A-Za-z0-9._+-]+$/',
						'placeholder' => '(all)',
						'next_to' => [
							'allowed_domain' => (Settings::Get('mail.allow_external_domains') == '0' ?
								[
									'next_to_prefix' => '@',
									'type' => 'select',
									'select_var' => $domains,
								]
								:
								[
								'next_to_prefix' => '@',
								'type' => 'text',
								'placeholder' => 'domain.tld',
								'mandatory' => true
							])
						]
					]
				]
			]
		]
	]
];
