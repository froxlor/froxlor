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

use Froxlor\UI\Callbacks\Mysql;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

// used outside scope variables
$multiple_mysqlservers = $multiple_mysqlservers ?? false;

return [
	'mysql_list' => [
		'title' => lng('menue.mysql.databases'),
		'icon' => 'fa-solid fa-database',
		'self_overview' => ['section' => 'mysql', 'page' => 'mysqls'],
		'default_sorting' => ['databasename' => 'asc'],
		'columns' => [
			'databasename' => [
				'label' => lng('mysql.databasename'),
				'field' => 'databasename',
			],
			'description' => [
				'label' => lng('mysql.databasedescription'),
				'field' => 'description'
			],
			'size' => [
				'label' => lng('mysql.size'),
				'field' => 'size',
				'callback' => [Text::class, 'size'],
				'searchable' => false
			],
			'dbserver' => [
				'label' => lng('mysql.mysql_server'),
				'field' => 'dbserver',
				'callback' => [Mysql::class, 'dbserver'],
				'visible' => $multiple_mysqlservers
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('mysql_list', [
			'databasename',
			'description',
			'size',
			'dbserver'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'mysql',
					'page' => 'mysqls',
					'action' => 'edit',
					'id' => ':id'
				],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'mysql',
					'page' => 'mysqls',
					'action' => 'delete',
					'id' => ':id'
				],
			]
		]
	]
];
