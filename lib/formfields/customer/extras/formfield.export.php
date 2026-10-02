<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2016 the froxlor Team (see authors).
 *
 * For the full copyright and license information, please view the COPYING
 * file that was distributed with this source code. You can also view the
 * COPYING file online at https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  (c) the authors
 * @author         froxlor team <team@froxlor.org> (2010-)
 * @license        GPLv2 https://files.froxlor.org/misc/COPYING.txt
 * @package        Formfields
 *
 */

use Froxlor\Settings;

return [
	'export' => [
		'title' => lng('extras.export'),
		'image' => 'fa-solid fa-server',
		'sections' => [
			'section_a' => [
				'title' => lng('extras.export'),
				'fields' => [
					'path' => [
						'label' => lng('panel.exportpath.title'),
						'desc' => lng('panel.exportpath.description') . '<br>' . (Settings::Get('panel.pathedit') != 'Dropdown' ? lng('panel.pathDescription') : null),
						'type' => $pathSelect['type'],
						'select_var' => $pathSelect['select_var'] ?? '',
						'selected' => $pathSelect['value'],
						'value' => $pathSelect['value'],
						'note' => $pathSelect['note'] ?? '',
					],
					'pgp_public_key' => [
						'label' => lng('panel.export_pgp_public_key.title'),
						'desc' => lng('panel.export_pgp_public_key.description'),
						'type' => 'textarea',
					],
					'path_protection_info' => [
						'label' => lng('extras.path_protection_label'),
						'type' => 'infotext',
						'value' => lng('extras.path_protection_info'),
						'classes' => 'fw-bold text-danger'
					],
					'dump_web' => [
						'label' => lng('extras.dump_web'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'dump_mail' => [
						'label' => lng('extras.dump_mail'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'dump_dbs' => [
						'label' => lng('extras.dump_dbs'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					]
				]
			]
		]
	]
];
