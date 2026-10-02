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
	'mysqlserver_add' => [
		'title' => lng('admin.mysqlserver.add'),
		'image' => 'fa-solid fa-plus',
		'self_overview' => ['section' => 'mysqlserver', 'page' => 'mysqlserver'],
		'sections' => [
			'section_a' => [
				'title' => lng('admin.mysqlserver.mysqlserver'),
				'fields' => [
					'mysql_host' => [
						'label' => lng('admin.mysqlserver.host'),
						'type' => 'text',
						'mandatory' => true
					],
					'mysql_port' => [
						'label' => lng('admin.mysqlserver.port'),
						'type' => 'number',
						'min' => 1,
						'max' => 65535,
						'value' => 3306,
						'mandatory' => true
					],
					'description' => [
						'label' => lng('admin.mysqlserver.caption'),
						'type' => 'text',
					],
					'privileged_user' => [
						'label' => lng('admin.mysqlserver.user'),
						'type' => 'text',
						'mandatory' => true
					],
					'privileged_password' => [
						'label' => lng('admin.mysqlserver.password'),
						'type' => 'password',
						'mandatory' => true
					],
					'allow_all_customers' => [
						'label' => lng('admin.mysqlserver.allowall'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'test_connection' => [
						'label' => lng('admin.mysqlserver.testconn'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					]
				]
			],
			'section_b' => [
				'title' => lng('admin.mysqlserver.ssl'),
				'fields' => [
					'mysql_ca' => [
						'label' => lng('admin.mysqlserver.ssl_cert_file'),
						'type' => 'text'
					],
					'mysql_verifycert' => [
						'label' => lng('admin.mysqlserver.verify_ca'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					]
				]
			]
		]
	]
];
