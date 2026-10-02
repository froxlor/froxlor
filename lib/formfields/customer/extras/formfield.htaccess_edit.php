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

use Froxlor\Settings;

return [
	'htaccess_edit' => [
		'title' => lng('extras.pathoptions_edit'),
		'image' => 'fa-solid fa-folder',
		'self_overview' => ['section' => 'extras', 'page' => 'htaccess'],
		'sections' => [
			'section_a' => [
				'title' => lng('extras.pathoptions_edit'),
				'fields' => [
					'path' => [
						'label' => lng('panel.path'),
						'type' => 'label',
						'value' => $result['path']
					],
					'options_indexes' => [
						'label' => lng('extras.directory_browsing'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['options_indexes']
					],
					'error404path' => [
						'label' => lng('extras.errordocument404path'),
						'desc' => lng('panel.descriptionerrordocument'),
						'type' => 'text',
						'value' => $result['error404path']
					],
					'error403path' => [
						'visible' => (Settings::Get('system.webserver') == 'apache2'),
						'label' => lng('extras.errordocument403path'),
						'desc' => lng('panel.descriptionerrordocument'),
						'type' => 'text',
						'value' => $result['error403path']
					],
					'error500path' => [
						'visible' => (Settings::Get('system.webserver') == 'apache2'),
						'label' => lng('extras.errordocument500path'),
						'desc' => lng('panel.descriptionerrordocument'),
						'type' => 'text',
						'value' => $result['error500path']
					],
					'options_cgi' => [
						'visible' => ($cperlenabled == 1),
						'label' => lng('extras.execute_perl'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['options_cgi']
					]
				]
			]
		]
	]
];
