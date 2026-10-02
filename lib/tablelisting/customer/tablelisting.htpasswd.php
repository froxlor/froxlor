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

use Froxlor\UI\Callbacks\Ftp;
use Froxlor\UI\Listing;

return [
	'htpasswd_list' => [
		'title' => lng('menue.extras.directoryprotection'),
		'icon' => 'fa-solid fa-lock',
		'self_overview' => ['section' => 'extras', 'page' => 'htpasswds'],
		'default_sorting' => ['path' => 'asc'],
		'columns' => [
			'username' => [
				'label' => lng('login.username'),
				'field' => 'username'
			],
			'path' => [
				'label' => lng('panel.path'),
				'field' => 'path',
				'callback' => [Ftp::class, 'pathRelative']
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('htpasswd_list', [
			'username',
			'path'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'extras',
					'page' => 'htpasswds',
					'action' => 'edit',
					'id' => ':id'
				],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'extras',
					'page' => 'htpasswds',
					'action' => 'delete',
					'id' => ':id'
				],
			]
		]
	]
];
