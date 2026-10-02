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
use Froxlor\UI\Callbacks\Customer;
use Froxlor\UI\Callbacks\Impersonate;
use Froxlor\UI\Callbacks\ProgressBar;
use Froxlor\UI\Callbacks\Style;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'admin_list' => [
		'title' => lng('admin.admin'),
		'icon' => 'fa-solid fa-user',
		'self_overview' => ['section' => 'admins', 'page' => 'admins'],
		'default_sorting' => ['loginname' => 'asc'],
		'columns' => [
			'adminid' => [
				'label' => 'ID',
				'field' => 'adminid',
				'sortable' => true,
			],
			'loginname' => [
				'label' => lng('login.username'),
				'field' => 'loginname',
				'callback' => [Impersonate::class, 'admin'],
				'sortable' => true,
				'isdefaultsearchfield' => true,
			],
			'name' => [
				'label' => lng('customer.name'),
				'field' => 'name',
			],
			'email' => [
				'label' => lng('login.email'),
				'field' => 'email',
			],
			'def_language' => [
				'label' => lng('login.profile_lng'),
				'field' => 'def_language',
			],
			'customers_used' => [
				'label' => lng('admin.customers'),
				'field' => 'customers_used',
				'class' => 'text-center',
			],
			'diskspace' => [
				'label' => lng('customer.diskspace'),
				'field' => 'diskspace',
				'callback' => [ProgressBar::class, 'diskspace'],
			],
			'traffic' => [
				'label' => lng('customer.traffic'),
				'field' => 'traffic',
				'callback' => [ProgressBar::class, 'traffic_admins'],
			],
			'caneditphpsettings' => [
				'label' => lng('admin.caneditphpsettings'),
				'field' => 'caneditphpsettings',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'change_serversettings' => [
				'label' => lng('admin.change_serversettings'),
				'field' => 'change_serversettings',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'deactivated' => [
				'label' => lng('admin.deactivated'),
				'field' => 'deactivated',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'lastlogin_succ' => [
				'label' => lng('admin.lastlogin_succ'),
				'field' => 'lastlogin_succ',
				'callback' => [Text::class, 'timestamp'],
			],
			'theme' => [
				'label' => lng('panel.theme'),
				'field' => 'theme',
				'callback' => [Text::class, 'escape'],
			],
			'api_allowed' => [
				'label' => lng('usersettings.api_allowed.title'),
				'field' => 'api_allowed',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'type_2fa' => [
				'label' => lng('2fa.type_2fa'),
				'field' => 'type_2fa',
				'class' => 'text-center',
				'callback' => [Text::class, 'type2fa'],
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('admin_list', [
			'loginname',
			'name',
			'customers_used',
			'diskspace',
			'traffic',
			'deactivated',
		]),
		'actions' => [
			'show' => [
				'icon' => 'fa-solid fa-eye',
				'title' => lng('usersettings.custom_notes.title'),
				'modal' => [Text::class, 'customerNoteDetailModal'],
				'visible' => [Customer::class, 'hasNote']
			],
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'admins',
					'page' => 'admins',
					'action' => 'edit',
					'id' => ':adminid'
				],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'admins',
					'page' => 'admins',
					'action' => 'delete',
					'id' => ':adminid'
				],
				'visible' => [Admin::class, 'isNotMe']
			],
		],
		'format_callback' => [
			[Style::class, 'deactivated'],
			[Style::class, 'diskspaceWarning'],
			[Style::class, 'trafficWarning']
		]
	]
];
