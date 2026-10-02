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
	'cron_list' => [
		'title' => lng('admin.cron.cronsettings'),
		'icon' => 'fa-solid fa-clock-rotate-left',
		'default_sorting' => ['c.id' => 'asc'],
		'no_search' => true,
		'columns' => [
			'c.desc_lng_key' => [
				'label' => lng('cron.description'),
				'field' => 'desc_lng_key',
				'callback' => [Text::class, 'crondesc']
			],
			'c.lastrun' => [
				'label' => lng('cron.lastrun'),
				'field' => 'lastrun',
				'callback' => [Text::class, 'timestamp']
			],
			'c.interval' => [
				'label' => lng('cron.interval'),
				'field' => 'interval'
			],
			'c.isactive' => [
				'label' => lng('cron.isactive'),
				'field' => 'isactive',
				'callback' => [Text::class, 'boolean']
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('cron_list', [
			'c.desc_lng_key',
			'c.lastrun',
			'c.interval',
			'c.isactive',
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'cronjobs',
					'page' => 'overview',
					'action' => 'edit',
					'id' => ':id'
				],
			]
		]
	]
];
