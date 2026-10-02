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

return [
	'dns_add' => [
		'title' => 'DNS Editor',
		'image' => 'fa-solid fa-globe',
		'sections' => [
			'section_a' => [
				'fields' => [
					'dns_record' => [
						'label' => 'Record',
						'type' => 'text',
						'value' => $record,
						'mandatory' => true
					],
					'dns_type' => [
						'label' => 'Type',
						'type' => 'select',
						'select_var' => [
							'A' => 'A',
							'AAAA' => 'AAAA',
							'CAA' => 'CAA',
							'CNAME' => 'CNAME',
							'DNAME' => 'DNAME',
							'LOC' => 'LOC',
							'MX' => 'MX',
							'NAPTR' => 'NAPTR',
							'NS' => 'NS',
							'RP' => 'RP',
							'SRV' => 'SRV',
							'SSHFP' => 'SSHFP',
							'TLSA' => 'TLSA',
							'TXT' => 'TXT'
						],
						'selected' => $type
					],
					'dns_mxp' => [
						'label' => 'Priority',
						'type' => 'number',
						'value' => $prio
					],
					'dns_content' => [
						'label' => 'Content',
						'type' => 'text',
						'value' => $content,
						'note' => lng('dnseditor.notes.A')
					],
					'dns_ttl' => [
						'label' => 'TTL',
						'type' => 'number',
						'min' => 30,
						'value' => $ttl
					]
				]
			]
		]
	]
];
