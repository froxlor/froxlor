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

// used outside scope variables
$cperlenabled = $cperlenabled ?? false;

return [
	'htaccess_list' => [
		'title' => lng('menue.extras.pathoptions'),
		'icon' => 'fa-solid fa-folder',
		'self_overview' => ['section' => 'extras', 'page' => 'htaccess'],
		'default_sorting' => ['path' => 'asc'],
		'columns' => [
			'path' => [
				'label' => lng('panel.path'),
				'field' => 'path',
				'callback' => [Ftp::class, 'pathRelative']
			],
			'options_indexes' => [
				'label' => lng('extras.view_directory'),
				'field' => 'options_indexes',
				'callback' => [Text::class, 'boolean']
			],
			'error404path' => [
				'label' => lng('extras.error404path'),
				'field' => 'error404path'
			],
			'error403path' => [
				'label' => lng('extras.error403path'),
				'field' => 'error403path'
			],
			'error500path' => [
				'label' => lng('extras.error500path'),
				'field' => 'error500path'
			],
			'options_cgi' => [
				'label' => lng('extras.execute_perl'),
				'field' => 'options_cgi',
				'callback' => [Text::class, 'boolean'],
				'visible' => $cperlenabled
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('htaccess_list', [
			'path',
			'options_indexes',
			'error404path',
			'error403path',
			'error500path',
			'options_cgi'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'extras',
					'page' => 'htaccess',
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
					'page' => 'htaccess',
					'action' => 'delete',
					'id' => ':id'
				],
			]
		]
	]
];
