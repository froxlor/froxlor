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
		'crond' => [
			'title' => lng('admin.cronsettings'),
			'icon' => 'fa-solid fa-clock-rotate-left',
			'advanced_mode' => true,
			'fields' => [
				'system_cronconfig' => [
					'label' => lng('serversettings.system_cronconfig'),
					'settinggroup' => 'system',
					'varname' => 'cronconfig',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/etc/cron.d/froxlor',
					'save_method' => 'storeSettingField'
				],
				'system_croncmdline' => [
					'label' => lng('serversettings.system_croncmdline'),
					'settinggroup' => 'system',
					'varname' => 'croncmdline',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => '/usr/bin/nice -n 5 /usr/bin/php -q',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_crondreload' => [
					'label' => lng('serversettings.system_crondreload'),
					'settinggroup' => 'system',
					'varname' => 'crondreload',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => '/etc/init.d/cron reload',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_cron_allowautoupdate' => [
					'label' => lng('serversettings.system_cron_allowautoupdate'),
					'settinggroup' => 'system',
					'varname' => 'cron_allowautoupdate',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'required_otp' => true
				]
			]
		]
	]
];
