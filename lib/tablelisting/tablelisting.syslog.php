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

use Froxlor\UI\Callbacks\SysLog;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'syslog_list' => [
		'title' => lng('menue.logger.logger'),
		'icon' => 'fa-solid fa-file-lines',
		'self_overview' => ['section' => 'logger', 'page' => 'log'],
		'default_sorting' => ['date' => 'desc'],
		'columns' => [
			'date' => [
				'label' => lng('logger.date'),
				'field' => 'date',
				'callback' => [Text::class, 'timestamp'],
			],
			'type' => [
				'label' => lng('logger.type'),
				'field' => 'type',
				'callback' => [SysLog::class, 'typeDescription'],
			],
			'user' => [
				'label' => lng('logger.user'),
				'field' => 'user',
			],
			'text' => [
				'label' => lng('logger.action'),
				'field' => 'text',
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('syslog_list', [
			'date',
			'type',
			'user',
			'text'
		])
	]
];
