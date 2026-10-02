<?php

use Froxlor\Settings;

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
	'mailtest' => [
		'title' => lng('admin.testmail'),
		'image' => 'fa-solid fa-paper-plane',
		'sections' => [
			'section_a' => [
				'fields' => [
					'smtp_user' => [
						'label' => lng('serversettings.mail_smtp_user'),
						'type' => 'label',
						'value' => (empty(Settings::Get('system.mail_smtp_user')) ? lng('panel.unspecified') : Settings::Get('system.mail_smtp_user'))
					],
					'smtp_host' => [
						'label' => lng('serversettings.mail_smtp_host'),
						'type' => 'label',
						'value' => (empty(Settings::Get('system.mail_smtp_host')) ? lng('panel.unspecified') : Settings::Get('system.mail_smtp_host'))
					],
					'smtp_port' => [
						'label' => lng('serversettings.mail_smtp_port'),
						'type' => 'label',
						'value' => (empty(Settings::Get('system.mail_smtp_port')) ? lng('panel.unspecified') : Settings::Get('system.mail_smtp_port'))
					],
					'smtp_auth' => [
						'label' => lng('serversettings.mail_smtp_auth'),
						'type' => 'checkbox',
						'value' => 1,
						'checked' => (bool)Settings::Get('system.mail_use_smtp'),
						'disabled' => true
					],
					'smtp_tls' => [
						'label' => lng('serversettings.mail_smtp_usetls'),
						'type' => 'checkbox',
						'value' => 1,
						'checked' => (bool)Settings::Get('system.mail_smtp_usetls'),
						'disabled' => true
					],
					'test_addr' => [
						'label' => lng('admin.smtptestaddr'),
						'type' => 'email',
						'mandatory' => true
					]
				]
			]
		],
		'buttons' => [
			[
				'label' => lng('admin.smtptestsend')
			]
		]
	]
];
