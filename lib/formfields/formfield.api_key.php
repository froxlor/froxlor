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
	'apikey' => [
		'title' => lng('menue.main.apikeys'),
		'sections' => [
			'section_a' => [
				'fields' => [
					'loginname' => [
						'label' => lng('login.username'),
						'type' => 'label',
						'value' => $result['loginname'] ?? $result['adminname']
					],
					'apikey' => [
						'label' => 'API key',
						'type' => 'text',
						'readonly' => true,
						'value' => $result['apikey']
					],
					'secret' => [
						'label' => 'Secret',
						'type' => 'text',
						'readonly' => true,
						'value' => $result['secret']
					],
					'allowed_from' => [
						'label' => [
							'title' => lng('apikeys.allowed_from'),
							'description' => lng('apikeys.allowed_from_help')
						],
						'type' => 'text',
						'value' => $result['allowed_from'],
					],
					'valid_until' => [
						'label' => [
							'title' => lng('apikeys.valid_until'),
							'description' => lng('apikeys.valid_until_help')
						],
						'type' => 'datetime-local',
						'value' => $result['valid_until'] < 0 ? "" : date('Y-m-d\TH:i', $result['valid_until'])
					]
				]
			]
		]
	]
];
