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
		'title' => lng('admin.domain_add'),
		'image' => 'fa-solid fa-globe',
		'self_overview' => ['section' => 'domains', 'page' => 'domains'],
		'id' => 'domain_add',
		'sections' => [
			'section_a' => [
				'title' => lng('domains.domainsettings'),
				'fields' => [
					'domain' => [
						'label' => 'Domain',
						'type' => 'text',
						'mandatory' => true
					],
					'customerid' => [
						'label' => lng('admin.customer'),
						'type' => 'select',
						'select_var' => $customers,
						'mandatory' => true
					],
					'adminid' => [
						'visible' => $userinfo['customers_see_all'] == '1',
						'label' => lng('admin.admin'),
						'type' => 'select',
						'select_var' => $admins,
						'selected' => $userinfo['adminid'],
						'mandatory' => true
					],
					'alias' => [
						'label' => lng('domains.aliasdomain'),
						'type' => 'select',
						'select_var' => $domains
					],
					'caneditdomain' => [
						'label' => lng('admin.domain_editable.title'),
						'desc' => lng('admin.domain_editable.desc'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'add_date' => [
						'label' => lng('domains.add_date'),
						'desc' => lng('panel.dateformat'),
						'type' => 'date',
						'readonly' => true,
						'value' => date('Y-m-d')
					],
					'registration_date' => [
						'label' => lng('domains.registration_date'),
						'desc' => lng('panel.dateformat'),
						'type' => 'date',
						'size' => 10
					],
					'termination_date' => [
						'label' => lng('domains.termination_date'),
						'desc' => lng('panel.dateformat'),
						'type' => 'date',
						'size' => 10
					]
				]
			],
			'section_e' => [
				'title' => lng('admin.mailserversettings'),
				'fields' => [
					'isemaildomain' => [
						'label' => lng('admin.emaildomain'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'email_only' => [
						'label' => lng('admin.email_only'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'subcanemaildomain' => [
						'label' => lng('admin.subdomainforemail'),
						'type' => 'select',
						'select_var' => $subcanemaildomain,
						'selected' => 0
					],
					'dkim' => [
						'visible' => Settings::Get('antispam.activated') == '1',
						'label' => 'DomainKeys',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					]
				]
			],
			'section_b' => [
				'title' => lng('admin.webserversettings'),
				'fields' => [
					'documentroot' => [
						'label' => 'DocumentRoot',
						'desc' => lng('panel.emptyfordefault'),
						'type' => 'text'
					],
					'ipandport' => [
						'label' => lng('domains.ipandport_multi.title'),
						'desc' => lng('domains.ipandport_multi.description'),
						'type' => 'checkbox',
						'values' => $ipsandports,
						'value' => explode(',', Settings::Get('system.defaultip')),
						'is_array' => 1,
						'mandatory' => true
					],
					'selectserveralias' => [
						'label' => lng('admin.selectserveralias'),
						'desc' => lng('admin.selectserveralias_desc'),
						'type' => 'select',
						'select_var' => $serveraliasoptions,
						'selected' => Settings::Get('system.domaindefaultalias')
					],
					'specialsettings' => [
						'visible' => $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.ownvhostsettings'),
						'desc' => lng('serversettings.default_vhostconf.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12
					],
					'notryfiles' => [
						'visible' => (Settings::Get('system.webserver') == 'nginx' && $userinfo['change_serversettings'] == '1'),
						'label' => lng('admin.notryfiles.title'),
						'desc' => lng('admin.notryfiles.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'writeaccesslog' => [
						'label' => lng('admin.writeaccesslog.title'),
						'desc' => lng('admin.writeaccesslog.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'writeerrorlog' => [
						'label' => lng('admin.writeerrorlog.title'),
						'desc' => lng('admin.writeerrorlog.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'speciallogfile' => [
						'label' => lng('admin.speciallogfile.title'),
						'desc' => lng('admin.speciallogfile.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
				]
			],
			'section_bssl' => [
				'title' => lng('admin.webserversettings_ssl'),
				'visible' => Settings::Get('system.use_ssl') == '1',
				'fields' => [
					'sslenabled' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_sslenabled'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => !empty(Settings::Get('system.defaultsslip'))
					],
					'no_ssl_available_info' => [
						'visible' => empty($ssl_ipsandports),
						'label' => 'SSL',
						'type' => 'label',
						'value' => lng('panel.nosslipsavailable')
					],
					'ssl_ipandport' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('domains.ipandport_ssl_multi.title'),
						'desc' => lng('domains.ipandport_multi.description'),
						'type' => 'checkbox',
						'values' => $ssl_ipsandports,
						'value' => explode(',', Settings::Get('system.defaultsslip')),
						'is_array' => 1
					],
					'ssl_redirect' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('domains.ssl_redirect.title'),
						'desc' => lng('domains.ssl_redirect.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'letsencrypt' => [
						'visible' => (Settings::Get('system.leenabled') == '1' && !empty($ssl_ipsandports)),
						'label' => lng('admin.letsencrypt.title'),
						'desc' => lng('admin.letsencrypt.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'http2' => [
						'visible' => !empty($ssl_ipsandports) && Settings::Get('system.http2_support') == '1',
						'label' => lng('admin.domain_http2.title'),
						'desc' => lng('admin.domain_http2.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'http3' => [
						'visible' => !empty($ssl_ipsandports) && Settings::Get('system.webserver') == 'nginx' && Settings::Get('system.http3_support') == '1',
						'label' => lng('admin.domain_http3.title'),
						'desc' => lng('admin.domain_http3.description') . lng('admin.domain_http3.nginx_version_warning'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'override_tls' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.domain_override_tls'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'ssl_protocols' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('serversettings.ssl.ssl_protocols.title'),
						'desc' => lng('serversettings.ssl.ssl_protocols.description').lng('admin.domain_override_tls_addinfo'),
						'type' => 'checkbox',
						'value' => explode(",", Settings::Get('system.ssl_protocols') ?? 'TLSv1.2'),
						'values' => [
							[
								'value' => 'TLSv1',
								'label' => 'TLSv1'
							],
							[
								'value' => 'TLSv1.1',
								'label' => 'TLSv1.1'
							],
							[
								'value' => 'TLSv1.2',
								'label' => 'TLSv1.2'
							],
							[
								'value' => 'TLSv1.3',
								'label' => 'TLSv1.3'
							]
						],
						'is_array' => 1
					],
					'ssl_cipher_list' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('serversettings.ssl.ssl_cipher_list.title'),
						'desc' => lng('serversettings.ssl.ssl_cipher_list.description').lng('admin.domain_override_tls_addinfo'),
						'type' => 'text',
						'value' => Settings::Get('system.ssl_cipher_list')
					],
					'tlsv13_cipher_list' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1' && Settings::Get('system.webserver') == "apache2" && Settings::Get('system.apache24') == 1,
						'label' => lng('serversettings.ssl.tlsv13_cipher_list.title'),
						'desc' => lng('serversettings.ssl.tlsv13_cipher_list.description').lng('admin.domain_override_tls_addinfo'),
						'type' => 'text',
						'value' => Settings::Get('system.tlsv13_cipher_list')
					],
					'ssl_specialsettings' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.ownsslvhostsettings'),
						'desc' => lng('serversettings.default_vhostconf.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12
					],
					'include_specialsettings' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('serversettings.includedefault_sslvhostconf'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'hsts_maxage' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_hsts_maxage.title'),
						'desc' => lng('admin.domain_hsts_maxage.description'),
						'type' => 'number',
						'min' => 0,
						'max' => 94608000, // 3-years
						'value' => 0
					],
					'hsts_sub' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_hsts_incsub.title'),
						'desc' => lng('admin.domain_hsts_incsub.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'hsts_preload' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_hsts_preload.title'),
						'desc' => lng('admin.domain_hsts_preload.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'ocsp_stapling' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_ocsp_stapling.title'),
						'desc' => lng('admin.domain_ocsp_stapling.description') . (Settings::Get('system.webserver') == 'nginx' ? lng('admin.domain_ocsp_stapling.nginx_version_warning') : ""),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'honorcipherorder' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_honorcipherorder'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => false
					],
					'sessiontickets' => [
						'visible' => !empty($ssl_ipsandports) && Settings::Get('system.sessionticketsenabled' != '1'),
						'label' => lng('admin.domain_sessiontickets'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					]
				]
			],
			'section_c' => [
				'title' => lng('admin.phpserversettings'),
				'visible' => $userinfo['change_serversettings'] == '1' || $userinfo['caneditphpsettings'] == '1',
				'fields' => [
					'openbasedir' => [
						'label' => 'OpenBasedir',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'openbasedir_path' => [
						'label' => lng('domain.openbasedirpath'),
						'type' => 'select',
						'select_var' => $openbasedir,
						'selected' => 0
					],
					'phpenabled' => [
						'label' => lng('admin.phpenabled'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'phpsettingid' => [
						'visible' => (int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1,
						'label' => lng('admin.phpsettings.title'),
						'type' => 'select',
						'select_var' => $phpconfigs,
						'selected' => (int)Settings::Get('phpfpm.enabled') == 1 ? Settings::Get('phpfpm.defaultini') : Settings::Get('system.mod_fcgid_defaultini')
					],
					'mod_fcgid_starter' => [
						'visible' => (int)Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.mod_fcgid_starter.title'),
						'type' => 'number'
					],
					'mod_fcgid_maxrequests' => [
						'visible' => (int)Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.mod_fcgid_maxrequests.title'),
						'type' => 'number'
					]
				]
			],
			'section_d' => [
				'title' => lng('admin.nameserversettings'),
				'visible' => Settings::Get('system.bind_enable') == '1' && $userinfo['change_serversettings'] == '1',
				'fields' => [
					'isbinddomain' => [
						'label' => lng('admin.createzonefile'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => true
					],
					'zonefile' => [
						'label' => lng('admin.custombindzone'),
						'desc' => lng('admin.bindzonewarning'),
						'type' => 'text'
					]
				]
			]
		]
	]
];
