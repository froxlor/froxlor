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
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'export_list' => [
		'title' => lng('error.customerhasongoingexportjob'),
		'icon' => 'fa-solid fa-server',
		'self_overview' => ['section' => 'extras', 'page' => 'export'],
		'default_sorting' => ['destdir' => 'asc'],
		'columns' => [
			'destdir' => [
				'label' => lng('panel.path'),
				'field' => 'data.destdir',
				'callback' => [Ftp::class, 'pathRelative']
			],
			'pgp_public_key' => [
				'label' => lng('panel.pgp_public_key'),
				'field' => 'data.pgp_public_key',
				'callback' => [Text::class, 'boolean']
			],
			'dump_web' => [
				'label' => lng('extras.dump_web'),
				'field' => 'data.dump_web',
				'callback' => [Text::class, 'boolean'],
			],
			'dump_mail' => [
				'label' => lng('extras.dump_mail'),
				'field' => 'data.dump_mail',
				'callback' => [Text::class, 'boolean'],
			],
			'dump_dbs' => [
				'label' => lng('extras.dump_dbs'),
				'field' => 'data.dump_dbs',
				'callback' => [Text::class, 'boolean'],
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('export_list', [
			'destdir',
			'pgp_public_key',
			'dump_web',
			'dump_mail',
			'dump_dbs'
		]),
		'actions' => [
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.abort'),
				'class' => 'btn-warning',
				'href' => [
					'section' => 'extras',
					'page' => 'export',
					'action' => 'abort',
					'id' => ':id'
				],
			]
		]
	]
];
