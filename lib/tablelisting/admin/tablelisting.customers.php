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

use Froxlor\UI\Callbacks\Customer;
use Froxlor\UI\Callbacks\Impersonate;
use Froxlor\UI\Callbacks\ProgressBar;
use Froxlor\UI\Callbacks\Style;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'customer_list' => [
		'title' => lng('admin.customers'),
		'description' => lng('admin.customers_list_desc'),
		'icon' => 'fa-solid fa-user',
		'self_overview' => ['section' => 'customers', 'page' => 'customers'],
		'default_sorting' => ['c.name' => 'asc'],
		'columns' => [
			'c.customerid' => [
				'label' => 'ID',
				'field' => 'customerid',
				'sortable' => true,
			],
			'c.name' => [
				'label' => lng('customer.name'),
				'field' => 'name',
				'callback' => [Text::class, 'customerfullname'],
			],
			'c.loginname' => [
				'label' => lng('login.username'),
				'field' => 'loginname',
				'callback' => [Impersonate::class, 'customer'],
			],
			'a.loginname' => [
				'label' => lng('admin.admin'),
				'field' => 'adminname',
				'callback' => [Impersonate::class, 'admin'],
			],
			'c.email' => [
				'label' => lng('customer.email'),
				'field' => 'email',
			],
			'c.street' => [
				'label' => lng('customer.street'),
				'field' => 'street',
			],
			'c.zipcode' => [
				'label' => lng('customer.zipcode'),
				'field' => 'zipcode',
			],
			'c.city' => [
				'label' => lng('customer.city'),
				'field' => 'city',
			],
			'c.phone' => [
				'label' => lng('customer.phone'),
				'field' => 'phone',
			],
			'c.fax' => [
				'label' => lng('customer.fax'),
				'field' => 'fax',
			],
			'c.customernumber' => [
				'label' => lng('customer.customernumber'),
				'field' => 'customernumber',
			],
			'c.def_language' => [
				'label' => lng('login.profile_lng'),
				'field' => 'def_language',
			],
			'c.guid' => [
				'label' => 'GUID',
				'field' => 'guid',
			],
			'c.diskspace' => [
				'label' => lng('customer.diskspace'),
				'field' => 'diskspace',
				'callback' => [ProgressBar::class, 'diskspace'],
			],
			'c.traffic' => [
				'label' => lng('customer.traffic'),
				'field' => 'traffic',
				'callback' => [ProgressBar::class, 'traffic'],
			],
			'c.deactivated' => [
				'label' => lng('admin.deactivated'),
				'field' => 'deactivated',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'c.lastlogin_succ' => [
				'label' => lng('admin.lastlogin_succ'),
				'field' => 'lastlogin_succ',
				'callback' => [Text::class, 'timestamp'],
			],
			'c.phpenabled' => [
				'label' => lng('admin.phpenabled'),
				'field' => 'phpenabled',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'c.perlenabled' => [
				'label' => lng('admin.perlenabled'),
				'field' => 'perlenabled',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'c.dnsenabled' => [
				'label' => lng('admin.dnsenabled'),
				'field' => 'dnsenabled',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'c.theme' => [
				'label' => lng('panel.theme'),
				'field' => 'theme',
				'callback' => [Text::class, 'escape'],
			],
			'c.logviewenabled' => [
				'label' => lng('admin.logviewenabled'),
				'field' => 'logviewenabled',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'c.api_allowed' => [
				'label' => lng('usersettings.api_allowed.title'),
				'field' => 'api_allowed',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
			],
			'c.type_2fa' => [
				'label' => lng('2fa.type_2fa'),
				'field' => 'type_2fa',
				'class' => 'text-center',
				'callback' => [Text::class, 'type2fa'],
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('customer_list', [
			'c.name',
			'c.loginname',
			'a.loginname',
			'c.email',
			'c.diskspace',
			'c.traffic',
		]),
		'actions' => [
			'show' => [
				'icon' => 'fa-solid fa-eye',
				'title' => lng('usersettings.custom_notes.title'),
				'modal' => [Text::class, 'customerNoteDetailModal'],
				'visible' => [Customer::class, 'hasNote']
			],
			'unlock' => [
				'icon' => 'fa-solid fa-unlock',
				'title' => lng('panel.unlock'),
				'class' => 'btn-outline-secondary',
				'href' => [
					'section' => 'customers',
					'page' => 'customers',
					'action' => 'unlock',
					'id' => ':customerid'
				],
				'visible' => [Customer::class, 'isLocked']
			],
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'customers',
					'page' => 'customers',
					'action' => 'edit',
					'id' => ':customerid'
				],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'customers',
					'page' => 'customers',
					'action' => 'delete',
					'id' => ':customerid'
				],
			],
		],
		'format_callback' => [
			[Style::class, 'resultCustomerLockedOrDeactivated']
		]
	]
];
