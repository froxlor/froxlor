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
	'domain_add' => [
		'title' => lng('domains.subdomain_add'),
		'image' => 'fa-solid fa-plus',
		'self_overview' => ['section' => 'domains', 'page' => 'domains'],
		'sections' => [
			'section_a' => [
				'title' => lng('domains.subdomain_add'),
				'fields' => [
					'subdomain' => [
						'label' => lng('domains.domainname'),
						'type' => 'text',
						'next_to' => [
							'domain' => [
								'next_to_prefix' => '.',
								'type' => 'select',
								'select_var' => $domains
							]
						]
					],
					'alias' => [
						'label' => lng('domains.aliasdomain'),
						'type' => 'select',
						'select_var' => $aliasdomains
					],
					'path' => [
						'label' => lng('panel.path'),
						'desc' => (Settings::Get('panel.pathedit') != 'Dropdown' ? lng('panel.pathDescriptionSubdomain').(Settings::Get('system.documentroot_use_default_value') == 1 ? lng('panel.pathDescriptionEx') : '') : null),
						'type' => $pathSelect['type'],
						'select_var' => $pathSelect['select_var'] ?? '',
						'selected' => $pathSelect['value'],
						'value' => $pathSelect['value'],
						'note' => $pathSelect['note'] ?? '',
					],
					'url' => [
						'visible' => Settings::Get('panel.pathedit') == 'Dropdown',
						'label' => lng('panel.urloverridespath'),
						'type' => 'text'
					],
					'redirectcode' => [
						'visible' => Settings::Get('customredirect.enabled') == '1',
						'label' => lng('domains.redirectifpathisurl'),
						'desc' => lng('domains.redirectifpathisurlinfo'),
						'type' => 'select',
						'select_var' => isset($redirectcode) ? $redirectcode : null
					],
					'selectserveralias' => [
						'label' => lng('admin.selectserveralias'),
						'desc' => lng('admin.selectserveralias_desc'),
						'type' => 'label',
						'value' => lng('customer.selectserveralias_addinfo')
					],
					'openbasedir_path' => [
						'label' => lng('domain.openbasedirpath'),
						'type' => 'select',
						'select_var' => $openbasedir
					],
					'phpsettingid' => [
						'visible' => ((int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1) && count($phpconfigs) > 0 && $userinfo['phpenabled'] == '1',
						'label' => lng('admin.phpsettings.title'),
						'type' => 'select',
						'select_var' => $phpconfigs,
						'selected' => (int)Settings::Get('phpfpm.enabled') == 1 ? Settings::Get('phpfpm.defaultini') : Settings::Get('system.mod_fcgid_defaultini')
					],
					'speciallogfile' => [
						'label' => lng('admin.speciallogfile.title'),
						'desc' => lng('admin.speciallogfile.description'),
						'type' => 'select',
						'select_var' => [
							0 => lng('panel.no'),
							1 => lng('panel.yes'),
							2 => lng('domain.inherited')
						],
						'selected' => 2
					],
				]
			],
			'section_bssl' => [
				'title' => lng('admin.webserversettings_ssl'),
				'visible' => Settings::Get('system.use_ssl') == '1' && $ssl_ipsandports,
				'fields' => [
					'sslenabled' => [
						'label' => lng('admin.domain_sslenabled'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'ssl_redirect' => [
						'label' => lng('domains.ssl_redirect.title'),
						'desc' => lng('domains.ssl_redirect.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'letsencrypt' => [
						'visible' => Settings::Get('system.leenabled') == '1',
						'label' => lng('customer.letsencrypt.title'),
						'desc' => lng('customer.letsencrypt.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'http2' => [
						'visible' => $ssl_ipsandports && Settings::Get('system.http2_support') == '1',
						'label' => lng('admin.domain_http2.title'),
						'desc' => lng('admin.domain_http2.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'http3' => [
						'visible' => $ssl_ipsandports && Settings::Get('system.webserver') == 'nginx' && Settings::Get('system.http3_support') == '1',
						'label' => lng('admin.domain_http3.title'),
						'desc' => lng('admin.domain_http3.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'hsts_maxage' => [
						'label' => lng('admin.domain_hsts_maxage.title'),
						'desc' => lng('admin.domain_hsts_maxage.description'),
						'type' => 'number',
						'min' => 0,
						'max' => 94608000, // 3-years
						'value' => 0
					],
					'hsts_sub' => [
						'label' => lng('admin.domain_hsts_incsub.title'),
						'desc' => lng('admin.domain_hsts_incsub.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'hsts_preload' => [
						'label' => lng('admin.domain_hsts_preload.title'),
						'desc' => lng('admin.domain_hsts_preload.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					]
				]
			]
		]
	]
];
