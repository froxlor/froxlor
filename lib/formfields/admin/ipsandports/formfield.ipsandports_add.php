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
	'ipsandports_add' => [
		'title' => lng('admin.ipsandports.add'),
		'image' => 'fa-solid fa-plus',
		'self_overview' => ['section' => 'ipsandports', 'page' => 'ipsandports'],
		'sections' => [
			'section_a' => [
				'title' => lng('admin.ipsandports.ipandport'),
				'fields' => [
					'ip' => [
						'label' => lng('admin.ipsandports.ip'),
						'type' => 'text',
						'mandatory' => true
					],
					'port' => [
						'label' => lng('admin.ipsandports.port'),
						'type' => 'number',
						'min' => 1,
						'max' => 65535,
						'value' => 80,
						'mandatory' => true
					]
				]
			],
			'section_b' => [
				'title' => lng('admin.ipsandports.webserverdefaultconfig'),
				'fields' => [
					'listen_statement' => [
						'visible' => Settings::Get('system.webserver') != 'nginx',
						'label' => lng('admin.ipsandports.create_listen_statement'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'namevirtualhost_statement' => [
						'visible' => Settings::Get('system.webserver') == 'apache2' && (int)Settings::Get('system.apache24') == 0,
						'label' => lng('admin.ipsandports.create_namevirtualhost_statement'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => Settings::Get('system.webserver') == 'apache2' && (int)Settings::Get('system.apache24') == 0
					],
					'vhostcontainer' => [
						'label' => lng('admin.ipsandports.create_vhostcontainer'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'docroot' => [
						'label' => lng('admin.ipsandports.docroot.title'),
						'desc' => lng('admin.ipsandports.docroot.description'),
						'type' => 'text'
					],
					'specialsettings' => [
						'label' => lng('admin.ownvhostsettings'),
						'desc' => lng('serversettings.default_vhostconf.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12
					],
					'vhostcontainer_servername_statement' => [
						'visible' => Settings::Get('system.webserver') == 'apache2',
						'label' => lng('admin.ipsandports.create_vhostcontainer_servername_statement'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					]
				]
			],
			'section_c' => [
				'title' => lng('admin.ipsandports.webserverdomainconfig'),
				'fields' => [
					'default_vhostconf_domain' => [
						'label' => lng('admin.ipsandports.default_vhostconf_domain'),
						'desc' => lng('serversettings.default_vhostconf_domain.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12
					],
					'ssl_default_vhostconf_domain' => [
						'visible' => Settings::Get('system.use_ssl') == 1,
						'label' => lng('admin.ipsandports.ssl_default_vhostconf_domain'),
						'desc' => lng('serversettings.default_vhostconf_domain.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12
					],
					'include_default_vhostconf_domain' => [
						'label' => lng('serversettings.includedefault_sslvhostconf'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					]
				]
			],
			'section_d' => [
				'title' => lng('admin.ipsandports.webserverssldomainconfig'),
				'visible' => Settings::Get('system.use_ssl') == 1,
				'fields' => [
					'ssl' => [
						'label' => lng('admin.ipsandports.enable_ssl'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'ssl_cert_file' => [
						'label' => lng('admin.ipsandports.ssl_cert_file'),
						'type' => 'text'
					],
					'ssl_key_file' => [
						'label' => lng('admin.ipsandports.ssl_key_file'),
						'type' => 'text'
					],
					'ssl_ca_file' => [
						'label' => lng('admin.ipsandports.ssl_ca_file'),
						'type' => 'text'
					],
					'ssl_cert_chainfile' => [
						'label' => lng('admin.ipsandports.ssl_cert_chainfile.title'),
						'desc' => lng('admin.ipsandports.ssl_cert_chainfile.description'),
						'type' => 'text'
					],
					'ssl_specialsettings' => [
						'label' => lng('admin.ownsslvhostsettings'),
						'desc' => lng('serversettings.default_vhostconf.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12
					],
					'include_specialsettings' => [
						'label' => lng('serversettings.includedefault_sslvhostconf'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					]
				]
			]
		]
	]
];
