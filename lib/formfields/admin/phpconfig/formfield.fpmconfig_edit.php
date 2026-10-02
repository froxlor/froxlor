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
	'fpmconfig_edit' => [
		'title' => lng('admin.fpmsettings.edit'),
		'image' => 'fa-solid fa-pen',
		'self_overview' => ['section' => 'phpsettings', 'page' => 'fpmdaemons'],
		'sections' => [
			'section_a' => [
				'title' => lng('admin.fpmsettings.edit'),
				'fields' => [
					'description' => [
						'label' => lng('admin.phpsettings.description'),
						'type' => 'text',
						'maxlength' => 50,
						'value' => $result['description'],
						'mandatory' => true
					],
					'reload_cmd' => [
						'label' => lng('serversettings.phpfpm_settings.reload'),
						'type' => 'text',
						'maxlength' => 255,
						'value' => $result['reload_cmd'],
						'mandatory' => true,
						'required_otp' => true
					],
					'config_dir' => [
						'label' => lng('serversettings.phpfpm_settings.configdir'),
						'type' => 'text',
						'maxlength' => 255,
						'value' => $result['config_dir'],
						'mandatory' => true
					],
					'pm' => [
						'label' => lng('serversettings.phpfpm_settings.pm'),
						'type' => 'select',
						'select_var' => [
							'static' => 'static',
							'dynamic' => 'dynamic',
							'ondemand' => 'ondemand'
						],
						'selected' => $result['pm']
					],
					'max_children' => [
						'label' => lng('serversettings.phpfpm_settings.max_children.title'),
						'desc' => lng('serversettings.phpfpm_settings.max_children.description'),
						'type' => 'number',
						'value' => $result['max_children'],
						'min' => 1
					],
					'start_servers' => [
						'label' => lng('serversettings.phpfpm_settings.start_servers.title'),
						'desc' => lng('serversettings.phpfpm_settings.start_servers.description'),
						'type' => 'number',
						'value' => $result['start_servers'],
						'min' => 1
					],
					'min_spare_servers' => [
						'label' => lng('serversettings.phpfpm_settings.min_spare_servers.title'),
						'desc' => lng('serversettings.phpfpm_settings.min_spare_servers.description'),
						'type' => 'number',
						'value' => $result['min_spare_servers']
					],
					'max_spare_servers' => [
						'label' => lng('serversettings.phpfpm_settings.max_spare_servers.title'),
						'desc' => lng('serversettings.phpfpm_settings.max_spare_servers.description'),
						'type' => 'number',
						'value' => $result['max_spare_servers']
					],
					'max_requests' => [
						'label' => lng('serversettings.phpfpm_settings.max_requests.title'),
						'desc' => lng('serversettings.phpfpm_settings.max_requests.description'),
						'type' => 'number',
						'value' => $result['max_requests']
					],
					'idle_timeout' => [
						'label' => lng('serversettings.phpfpm_settings.idle_timeout.title'),
						'desc' => lng('serversettings.phpfpm_settings.idle_timeout.description'),
						'type' => 'number',
						'value' => $result['idle_timeout']
					],
					'limit_extensions' => [
						'label' => lng('serversettings.phpfpm_settings.limit_extensions.title'),
						'desc' => lng('serversettings.phpfpm_settings.limit_extensions.description'),
						'type' => 'text',
						'value' => $result['limit_extensions']
					],
					'custom_config' => [
						'label' => lng('serversettings.phpfpm_settings.custom_config.title'),
						'desc' => lng('serversettings.phpfpm_settings.custom_config.description'),
						'type' => 'textarea',
						'cols' => 50,
						'rows' => 7,
						'value' => $result['custom_config']
					]
				]
			]
		]
	],
	'fpmconfig_replacers' => [
		'replacers' => [
			[
				'var' => 'PEAR_DIR',
				'description' => lng('admin.phpconfig.pear_dir')
			],
			[
				'var' => 'OPEN_BASEDIR_C',
				'description' => lng('admin.phpconfig.open_basedir_c')
			],
			[
				'var' => 'OPEN_BASEDIR',
				'description' => lng('admin.phpconfig.open_basedir')
			],
			[
				'var' => 'OPEN_BASEDIR_GLOBAL',
				'description' => lng('admin.phpconfig.open_basedir_global')
			],
			[
				'var' => 'TMP_DIR',
				'description' => lng('admin.phpconfig.tmp_dir')
			],
			[
				'var' => 'CUSTOMER_EMAIL',
				'description' => lng('admin.phpconfig.customer_email')
			],
			[
				'var' => 'ADMIN_EMAIL',
				'description' => lng('admin.phpconfig.admin_email')
			],
			[
				'var' => 'DOMAIN',
				'description' => lng('admin.phpconfig.domain')
			],
			[
				'var' => 'CUSTOMER',
				'description' => lng('admin.phpconfig.customer')
			],
			[
				'var' => 'ADMIN',
				'description' => lng('admin.phpconfig.admin')
			],
			[
				'var' => 'DOCUMENT_ROOT',
				'description' => lng('admin.phpconfig.docroot')
			],
			[
				'var' => 'CUSTOMER_HOMEDIR',
				'description' => lng('admin.phpconfig.homedir')
			]
		]
	]
];
