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
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'ipsandports_list' => [
		'title' => lng('admin.ipsandports.ipsandports'),
		'icon' => 'fa-solid fa-ethernet',
		'self_overview' => ['section' => 'ipsandports', 'page' => 'ipsandports'],
		'default_sorting' => ['ip' => 'asc'],
		'columns' => [
			'ip' => [
				'label' => lng('admin.ipsandports.ip'),
				'field' => 'ip',
				'isdefaultsearchfield' => true,
			],
			'port' => [
				'label' => lng('admin.ipsandports.port'),
				'field' => 'port',
				'class' => 'text-center',
			],
			'listen' => [
				'label' => 'Listen',
				'field' => 'listen_statement',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
				'visible' => Settings::Get('system.webserver') != 'nginx'
			],
			'namevirtualhost' => [
				'label' => 'NameVirtualHost',
				'field' => 'namevirtualhost_statement',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
				'visible' => Settings::Get('system.webserver') == 'apache2' && (int)Settings::Get('system.apache24') == 0
			],
			'vhostcontainer' => [
				'label' => 'vHost-Container',
				'field' => 'vhostcontainer',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean']
			],
			'servername' => [
				'label' => lng('admin.ipsandports.create_vhostcontainer_servername_statement'),
				'field' => 'vhostcontainer_servername_statement',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean'],
				'visible' => Settings::Get('system.webserver') == 'apache2'
			],
			'specialsettings' => [
				'label' => 'Specialsettings',
				'field' => 'specialsettings',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean']
			],
			'ssl' => [
				'label' => 'SSL',
				'field' => 'ssl',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean']
			],
			'ssl_cert_file' => [
				'label' => lng('admin.ipsandports.ssl_cert_file'),
				'field' => 'ssl_cert_file',
				'class' => 'text-center',
			],
			'ssl_key_file' => [
				'label' => lng('admin.ipsandports.ssl_key_file'),
				'field' => 'ssl_key_file',
				'class' => 'text-center',
			],
			'ssl_ca_file' => [
				'label' => lng('admin.ipsandports.ssl_ca_file'),
				'field' => 'ssl_ca_file',
				'class' => 'text-center',
			],
			'ssl_cert_chainfile' => [
				'label' => lng('admin.ipsandports.ssl_cert_chainfile.title'),
				'field' => 'ssl_cert_chainfile',
				'class' => 'text-center',
			],
			'docroot' => [
				'label' => lng('admin.ipsandports.docroot.title'),
				'field' => 'docroot',
				'class' => 'text-center',
			],
			'ssl_specialsettings' => [
				'label' => 'SSL Specialsettings',
				'field' => 'ssl_specialsettings',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean']
			],
			'include_specialsettings' => [
				'label' => lng('serversettings.includedefault_sslvhostconf'),
				'field' => 'include_specialsettings',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean']
			],
			'ssl_default_vhostconf_domain' => [
				'label' => lng('admin.ipsandports.ssl_default_vhostconf_domain'),
				'field' => 'ssl_default_vhostconf_domain',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean']
			],
			'include_default_vhostconf_domain' => [
				'label' => '[Domains] '. lng('serversettings.includedefault_sslvhostconf'),
				'field' => 'include_default_vhostconf_domain',
				'class' => 'text-center',
				'callback' => [Text::class, 'boolean']
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('ipsandports_list', [
			'ip',
			'port',
			'vhostcontainer',
			'specialsettings',
			'servername',
			'ssl'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'ipsandports',
					'page' => 'ipsandports',
					'action' => 'edit',
					'id' => ':id'
				],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'ipsandports',
					'page' => 'ipsandports',
					'action' => 'delete',
					'id' => ':id'
				],
			],
		]
	]
];
