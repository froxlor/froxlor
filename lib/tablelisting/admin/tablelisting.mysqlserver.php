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
use Froxlor\UI\Listing;

return [
	'mysqlserver_list' => [
		'title' => lng('admin.mysqlserver.mysqlserver'),
		'icon' => 'fa-solid fa-server',
		'self_overview' => ['section' => 'mysqlserver', 'page' => 'mysqlserver'],
		'default_sorting' => ['caption' => 'asc'],
		'columns' => [
			'id' => [
				'label' => lng('admin.mysqlserver.dbserver'),
				'field' => 'id',
			],
			'caption' => [
				'label' => lng('admin.mysqlserver.caption'),
				'field' => 'caption',
				'isdefaultsearchfield' => true,
			],
			'host' => [
				'label' => lng('admin.mysqlserver.host'),
				'field' => 'host',
			],
			'port' => [
				'label' => lng('admin.mysqlserver.port'),
				'field' => 'port',
				'class' => 'text-center',
			],
			'user' => [
				'label' => lng('admin.mysqlserver.user'),
				'field' => 'user',
				'visible' => [Admin::class, 'canChangeServerSettings']
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('mysqlserver_list', [
			'caption',
			'host',
			'port',
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'mysqlserver',
					'page' => 'mysqlserver',
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
					'section' => 'mysqlserver',
					'page' => 'mysqlserver',
					'action' => 'delete',
					'id' => ':id'
				],
				'visible' => [Admin::class, 'canChangeServerSettings']
			],
		]
	]
];
