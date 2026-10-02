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

use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'plan_list' => [
		'title' => lng('admin.plans.plans'),
		'icon' => 'fa-solid fa-clipboard-list',
		'self_overview' => ['section' => 'plans', 'page' => 'overview'],
		'default_sorting' => ['p.name' => 'asc'],
		'columns' => [
			'p.id' => [
				'label' => 'ID',
				'field' => 'id',
			],
			'p.name' => [
				'label' => lng('admin.plans.name'),
				'field' => 'name',
				'isdefaultsearchfield' => true,
			],
			'p.description' => [
				'label' => lng('admin.plans.description'),
				'field' => 'description',
			],
			'p.adminname' => [
				'label' => lng('admin.admin'),
				'field' => 'adminname',
			],
			'p.ts' => [
				'label' => lng('admin.plans.last_update'),
				'field' => 'ts',
				'callback' => [Text::class, 'timestamp'],
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('plan_list', [
			'p.name',
			'p.description',
			'p.adminname',
			'p.ts',
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'plans',
					'page' => 'overview',
					'action' => 'edit',
					'id' => ':id'
				],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'plans',
					'page' => 'overview',
					'action' => 'delete',
					'id' => ':id'
				],
			],
		]
	]
];
