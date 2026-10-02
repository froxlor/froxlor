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
use Froxlor\UI\Callbacks\Admin;
use Froxlor\UI\Callbacks\PHPConf;
use Froxlor\UI\Listing;

return [
	'phpconf_list' => [
		'title' => lng('menue.phpsettings.maintitle'),
		'icon' => 'fa-brands fa-php',
		'self_overview' => ['section' => 'phpsettings', 'page' => 'overview'],
		'default_sorting' => ['c.description' => 'asc'],
		'columns' => [
			'c.id' => [
				'label' => 'ID',
				'field' => 'id',
			],
			'c.description' => [
				'label' => lng('admin.phpsettings.description'),
				'field' => 'description',
				'isdefaultsearchfield' => true,
			],
			'domains' => [
				'label' => lng('admin.phpsettings.activedomains'),
				'field' => 'domains',
				'callback' => [PHPConf::class, 'domainList'],
				'searchable' => false,
				'sortable' => false,
			],
			'fpmdesc' => [
				'label' => lng('admin.phpsettings.fpmdesc'),
				'field' => 'fpmdesc',
				'visible' => (bool)Settings::Get('phpfpm.enabled'),
				'callback' => [PHPConf::class, 'fpmConfLink']
			],
			'c.binary' => [
				'label' => lng('admin.phpsettings.binary'),
				'field' => 'binary',
				'visible' => !(bool)Settings::Get('phpfpm.enabled')
			],
			'c.file_extensions' => [
				'label' => lng('admin.phpsettings.file_extensions'),
				'field' => 'file_extensions',
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('phpconf_list', [
			'c.description',
			'domains',
			'fpmdesc',
			'c.binary',
			'c.file_extensions'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'phpsettings',
					'page' => 'overview',
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
					'page' => 'overview',
					'action' => 'delete',
					'id' => ':id'
				],
				'visible' => [PHPConf::class, 'isNotDefault']
			]
		]
	]
];
