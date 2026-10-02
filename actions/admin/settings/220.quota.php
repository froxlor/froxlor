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
		'diskquota' => [
			'title' => lng('diskquota'),
			'icon' => 'fa-solid fa-sliders',
			'advanced_mode' => true,
			'fields' => [
				'system_diskquota_enabled' => [
					'label' => lng('serversettings.diskquota_enabled'),
					'settinggroup' => 'system',
					'varname' => 'diskquota_enabled',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'overview_option' => true
				],
				'system_diskquota_repquota_path' => [
					'label' => lng('serversettings.diskquota_repquota_path.description'),
					'settinggroup' => 'system',
					'varname' => 'diskquota_repquota_path',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/usr/sbin/repquota',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_diskquota_quotatool_path' => [
					'label' => lng('serversettings.diskquota_quotatool_path.description'),
					'settinggroup' => 'system',
					'varname' => 'diskquota_quotatool_path',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/usr/bin/quotatool',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_diskquota_customer_partition' => [
					'label' => lng('serversettings.diskquota_customer_partition.description'),
					'settinggroup' => 'system',
					'varname' => 'diskquota_customer_partition',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/dev/root',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				]
			]
		]
	]
];
