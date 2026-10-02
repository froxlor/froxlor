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

use Froxlor\UI\Callbacks\Style;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'integrity_list' => [
		'title' => lng('admin.integritycheck'),
		'icon' => 'fa-solid fa-circle-check',
		'self_overview' => ['section' => 'settings', 'page' => 'integritycheck'],
		'default_sorting' => ['displayid' => 'asc'],
		'no_search' => true,
		'columns' => [
			'displayid' => [
				'label' => 'ID',
				'field' => 'displayid'
			],
			'checkdesc' => [
				'label' => lng('admin.integrityname'),
				'field' => 'checkdesc'
			],
			'result' => [
				'label' => lng('admin.integrityresult'),
				'field' => 'result',
				'callback' => [Text::class, 'boolean'],
				'searchable' => false,
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('integrity_list', [
			'displayid',
			'checkdesc',
			'result'
		]),
		'format_callback' => [
			[Style::class, 'resultIntegrityBad']
		]
	]
];
