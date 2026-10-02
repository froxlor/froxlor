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

use Froxlor\UI\Callbacks\Impersonate;
use Froxlor\UI\Callbacks\Style;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'apikeys_list' => [
		'title' => lng('menue.main.apikeys'),
		'icon' => 'fa-solid fa-key',
		'self_overview' => ['section' => 'index', 'page' => 'apikeys'],
		'no_search' => true,
		'columns' => [
			'a.loginname' => [
				'label' => lng('login.username'),
				'field' => 'loginname',
				'callback' => [Impersonate::class, 'apiAdminCustomerLink']
			],
			'ak.apikey' => [
				'label' => 'API-key',
				'field' => 'apikey',
				'callback' => [Text::class, 'shorten'],
			],
			'ak.secret' => [
				'label' => 'Secret',
				'field' => 'secret',
				'callback' => [Text::class, 'shorten'],
			],
			'ak.allowed_from' => [
				'label' => lng('apikeys.allowed_from'),
				'field' => 'allowed_from',
			],
			'ak.valid_until' => [
				'label' => lng('apikeys.valid_until'),
				'field' => 'valid_until',
				'callback' => [Text::class, 'timestampUntil'],
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('apikeys_list', [
			'a.loginname',
			'ak.apikey',
			'ak.secret',
			'ak.allowed_from',
			'ak.valid_until'
		]),
		'actions' => [
			'show' => [
				'icon' => 'fa-solid fa-eye',
				'title' => lng('apikeys.clicktoview'),
				'modal' => [Text::class, 'apikeyDetailModal'],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'index',
					'page' => 'apikeys',
					'action' => 'delete',
					'id' => ':id'
				],
			],
		],
		'format_callback' => [
			[Style::class, 'invalidApiKey']
		]
	]
];
