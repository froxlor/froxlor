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
	'domain_ssleditor' => [
		'title' => lng('panel.ssleditor'),
		'image' => 'fa-solid fa-lock',
		'sections' => [
			'section_a' => [
				'title' => 'SSL certificates',
				'fields' => [
					'domainname' => [
						'label' => lng('domains.domainname'),
						'type' => 'label',
						'value' => $result_domain['domain']
					],
					'ssl_cert_file' => [
						'label' => lng('admin.ipsandports.ssl_cert_file_content'),
						'desc' => lng('admin.ipsandports.ssl_paste_description'),
						'type' => 'textarea',
						'cols' => 100,
						'rows' => 15,
						'value' => $result['ssl_cert_file'],
						'placeholder' => lng('domain.ssl_certificate_placeholder'),
						'mandatory' => true
					],
					'ssl_key_file' => [
						'label' => lng('admin.ipsandports.ssl_key_file_content'),
						'desc' => lng('admin.ipsandports.ssl_paste_description'),
						'type' => 'textarea',
						'cols' => 100,
						'rows' => 15,
						'value' => $result['ssl_key_file'],
						'placeholder' => lng('domain.ssl_key_placeholder'),
						'mandatory' => true
					],
					'ssl_cert_chainfile' => [
						'label' => lng('admin.ipsandports.ssl_cert_chainfile_content'),
						'desc' => lng('admin.ipsandports.ssl_paste_description') . lng('admin.ipsandports.ssl_cert_chainfile_content_desc'),
						'type' => 'textarea',
						'cols' => 100,
						'rows' => 15,
						'value' => $result['ssl_cert_chainfile']
					],
					'ssl_ca_file' => [
						'label' => lng('admin.ipsandports.ssl_ca_file_content'),
						'desc' => lng('admin.ipsandports.ssl_paste_description') . lng('admin.ipsandports.ssl_ca_file_content_desc'),
						'type' => 'textarea',
						'cols' => 100,
						'rows' => 15,
						'value' => $result['ssl_ca_file']
					],
					'do_insert' => [
						'type' => 'hidden',
						'value' => '1',
						'visible' => empty($result['ssl_cert_file'])
					]
				]
			]
		]
	]
];
