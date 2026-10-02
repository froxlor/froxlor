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

use Froxlor\UI\Callbacks\Admin;
use Froxlor\UI\Callbacks\PHPConf;
use Froxlor\UI\Listing;

return [
	'fpmconf_list' => [
		'title' => lng('menue.phpsettings.fpmdaemons'),
		'icon' => 'fa-brands fa-php',
		'self_overview' => ['section' => 'phpsettings', 'page' => 'fpmdaemons'],
		'default_sorting' => ['description' => 'asc'],
		'columns' => [
			'id' => [
				'label' => 'ID',
				'field' => 'id'
			],
			'description' => [
				'label' => lng('admin.phpsettings.description'),
				'field' => 'description',
				'isdefaultsearchfield' => true,
			],
			'configs' => [
				'label' => lng('admin.phpsettings.activephpconfigs'),
				'callback' => [PHPConf::class, 'configsList'],
				'searchable' => false,
			],
			'reload_cmd' => [
				'label' => lng('serversettings.phpfpm_settings.reload'),
				'field' => 'reload_cmd'
			],
			'config_dir' => [
				'label' => lng('serversettings.phpfpm_settings.configdir'),
				'field' => 'config_dir'
			],
			'pm' => [
				'label' => lng('serversettings.phpfpm_settings.pm'),
				'field' => 'pm',
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('fpmconf_list', [
			'description',
			'configs',
			'reload_cmd',
			'config_dir',
			'pm'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'phpsettings',
					'page' => 'fpmdaemons',
					'action' => 'edit',
					'id' => ':id'
				],
				'visible' => [Admin::class, 'canChangeServerSettings']
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'phpsettings',
					'page' => 'fpmdaemons',
					'action' => 'delete',
					'id' => ':id'
				],
				'visible' => [PHPConf::class, 'isNotDefault']
			]
		]
	]
];
