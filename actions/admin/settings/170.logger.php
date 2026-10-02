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
		'logging' => [
			'title' => lng('admin.loggersettings'),
			'icon' => 'fa-solid fa-file-lines',
			'fields' => [
				'logger_enabled' => [
					'label' => lng('serversettings.logger.enable'),
					'settinggroup' => 'logger',
					'varname' => 'enabled',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'overview_option' => true
				],
				'logger_severity' => [
					'label' => lng('serversettings.logger.severity'),
					'settinggroup' => 'logger',
					'varname' => 'severity',
					'type' => 'select',
					'default' => 1,
					'select_var' => [
						1 => lng('admin.logger.normal'),
						2 => lng('admin.logger.paranoid')
					],
					'save_method' => 'storeSettingField'
				],
				'logger_logtypes' => [
					'label' => lng('serversettings.logger.types'),
					'settinggroup' => 'logger',
					'varname' => 'logtypes',
					'type' => 'select',
					'default' => 'syslog,mysql',
					'select_mode' => 'multiple',
					'select_var' => [
						'syslog' => 'syslog',
						'file' => 'file',
						'mysql' => 'mysql'
					],
					'save_method' => 'storeSettingField'
				],
				'logger_logfile' => [
					'label' => lng('serversettings.logger.logfile'),
					'settinggroup' => 'logger',
					'varname' => 'logfile',
					'type' => 'text',
					'string_type' => 'file',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'logger_log_cron' => [
					'label' => lng('serversettings.logger.logcron'),
					'settinggroup' => 'logger',
					'varname' => 'log_cron',
					'type' => 'select',
					'default' => 0,
					'select_var' => [
						0 => lng('serversettings.logger.logcronoption.never'),
						1 => lng('serversettings.logger.logcronoption.once'),
						2 => lng('serversettings.logger.logcronoption.always')
					],
					'save_method' => 'storeSettingField'
				]
			]
		]
	]
];
