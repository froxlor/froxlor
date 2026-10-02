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
	'domain_edit' => [
		'title' => lng('admin.domain_edit'),
		'image' => 'fa-solid fa-globe',
		'self_overview' => ['section' => 'domains', 'page' => 'domains'],
		'id' => 'domain_edit',
		'sections' => [
			'section_a' => [
				'title' => lng('domains.domainsettings'),
				'fields' => [
					'domain' => [
						'label' => 'Domain',
						'type' => 'label',
						'value' => $result['domain_ace']
					],
					'customerid' => [
						'label' => lng('admin.customer'),
						'type' => (Settings::Get('panel.allow_domain_change_customer') == '1' ? 'select' : 'infotext'),
						'select_var' => (isset($customers) ? $customers : null),
						'selected' => $result['customerid'],
						'value' => (isset($result['customername']) ? $result['customername'] : null),
						'mandatory' => true
					],
					'adminid' => [
						'visible' => $userinfo['customers_see_all'] == '1',
						'label' => lng('admin.admin'),
						'type' => (Settings::Get('panel.allow_domain_change_admin') == '1' ? 'select' : 'infotext'),
						'select_var' => (!empty($admins) ? $admins : null),
						'selected' => (isset($result['adminid']) ? $result['adminid'] : $userinfo['adminid']),
						'value' => (isset($result['adminname']) ? $result['adminname'] : null),
						'mandatory' => true
					],
					'alias' => [
						'visible' => $alias_check == '0',
						'label' => lng('domains.aliasdomain'),
						'type' => 'select',
						'select_var' => $domains,
						'selected' => $result['aliasdomain']
					],
					'associated_info' => [
						'label' => lng('domains.associated_with_domain'),
						'type' => 'label',
						'value' => $subdomains . ' ' . lng('customer.subdomains') . ', ' . $alias_check . ' ' . lng('domains.aliasdomains') . ', ' . $emails . ' ' . lng('customer.emails') . ', ' . $email_accounts . ' ' . lng('customer.accounts') . ', ' . $email_forwarders . ' ' . lng('customer.forwarders')
					],
					'caneditdomain' => [
						'label' => lng('admin.domain_editable.title'),
						'desc' => lng('admin.domain_editable.desc'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['caneditdomain']
					],
					'add_date' => [
						'label' => lng('domains.add_date'),
						'desc' => lng('panel.dateformat'),
						'type' => 'date',
						'readonly' => true,
						'value' => date('Y-m-d', (int)$result['add_date'])
					],
					'registration_date' => [
						'label' => lng('domains.registration_date'),
						'desc' => lng('panel.dateformat'),
						'type' => 'date',
						'value' => $result['registration_date'],
						'size' => 10
					],
					'termination_date' => [
						'label' => lng('domains.termination_date'),
						'desc' => lng('panel.dateformat'),
						'type' => 'date',
						'value' => $result['termination_date'],
						'size' => 10
					],
					'deactivated' => [
						'label' => lng('admin.deactivated'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['deactivated']
					],
				]
			],
			'section_e' => [
				'title' => lng('admin.mailserversettings'),
				'fields' => [
					'isemaildomain' => [
						'label' => lng('admin.emaildomain'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['isemaildomain']
					],
					'email_only' => [
						'label' => lng('admin.email_only'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['email_only']
					],
					'subcanemaildomain' => [
						'label' => lng('admin.subdomainforemail'),
						'type' => 'select',
						'select_var' => $subcanemaildomain,
						'selected' => $result['subcanemaildomain']
					],
					'dkim' => [
						'visible' => Settings::Get('antispam.activated') == '1',
						'label' => 'DomainKeys',
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['dkim']
					]
				]
			],
			'section_b' => [
				'title' => lng('admin.webserversettings'),
				'fields' => [
					'documentroot' => [
						'label' => 'DocumentRoot',
						'desc' => lng('panel.emptyfordefault'),
						'type' => 'text',
						'value' => $result['documentroot']
					],
					'ipandport' => [
						'label' => lng('domains.ipandport_multi.title'),
						'desc' => lng('domains.ipandport_multi.description'),
						'type' => 'checkbox',
						'values' => $ipsandports,
						'value' => $usedips,
						'is_array' => 1,
						'mandatory' => true
					],
					'selectserveralias' => [
						'label' => lng('admin.selectserveralias'),
						'desc' => lng('admin.selectserveralias_desc'),
						'type' => 'select',
						'select_var' => $serveraliasoptions,
						'selected' => $result['iswildcarddomain'] == '1' ? 0 : ($result['wwwserveralias'] == '1' ? 1 : 2)
					],
					'specialsettings' => [
						'visible' => $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.ownvhostsettings'),
						'desc' => lng('serversettings.default_vhostconf.description'),
						'type' => 'textarea',
						'value' => $result['specialsettings'],
						'cols' => 60,
						'rows' => 12
					],
					'specialsettingsforsubdomains' => [
						'visible' => $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.specialsettingsforsubdomains'),
						'desc' => lng('serversettings.specialsettingsforsubdomains.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => Settings::Get('system.apply_specialsettings_default') == 1 ? '1' : '0'
					],
					'notryfiles' => [
						'visible' => (Settings::Get('system.webserver') == 'nginx' && $userinfo['change_serversettings'] == '1'),
						'label' => lng('admin.notryfiles.title'),
						'desc' => lng('admin.notryfiles.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['notryfiles']
					],
					'writeaccesslog' => [
						'label' => lng('admin.writeaccesslog.title'),
						'desc' => lng('admin.writeaccesslog.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['writeaccesslog']
					],
					'writeerrorlog' => [
						'label' => lng('admin.writeerrorlog.title'),
						'desc' => lng('admin.writeerrorlog.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['writeerrorlog']
					],
					'speciallogfile' => [
						'label' => lng('admin.speciallogfile.title'),
						'desc' => lng('admin.speciallogfile.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['speciallogfile']
					],
					'speciallogverified' => [
						'type' => 'hidden',
						'value' => '0'
					],
					'emaildomainverified' => [
						'type' => 'hidden',
						'value' => '0'
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
						'checked' => $result['ssl_enabled']
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
						'value' => $usedips,
						'is_array' => 1
					],
					'ssl_redirect' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('domains.ssl_redirect.title'),
						'desc' => lng('domains.ssl_redirect.description') . ($result['temporary_ssl_redirect'] > 1 ? lng('domains.ssl_redirect_temporarilydisabled') : ''),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['ssl_redirect']
					],
					'letsencrypt' => [
						'visible' => (Settings::Get('system.leenabled') == '1' && !empty($ssl_ipsandports)),
						'label' => lng('admin.letsencrypt.title'),
						'desc' => lng('admin.letsencrypt.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['letsencrypt']
					],
					'http2' => [
						'visible' => !empty($ssl_ipsandports) && Settings::Get('system.http2_support') == '1',
						'label' => lng('admin.domain_http2.title'),
						'desc' => lng('admin.domain_http2.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['http2']
					],
					'http3' => [
						'visible' => !empty($ssl_ipsandports) && Settings::Get('system.webserver') == 'nginx' && Settings::Get('system.http3_support') == '1',
						'label' => lng('admin.domain_http3.title'),
						'desc' => lng('admin.domain_http3.description') . lng('admin.domain_http3.nginx_version_warning'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['http3']
					],
					'override_tls' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.domain_override_tls'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['override_tls']
					],
					'ssl_protocols' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('serversettings.ssl.ssl_protocols.title'),
						'desc' => lng('serversettings.ssl.ssl_protocols.description').lng('admin.domain_override_tls_addinfo'),
						'type' => 'checkbox',
						'value' => !empty($result['ssl_protocols']) ? explode(",", $result['ssl_protocols']) : explode(",", Settings::Get('system.ssl_protocols')),
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
						'value' => !empty($result['ssl_cipher_list']) ? $result['ssl_cipher_list'] : Settings::Get('system.ssl_cipher_list')
					],
					'tlsv13_cipher_list' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1' && Settings::Get('system.webserver') == "apache2" && Settings::Get('system.apache24') == 1,
						'label' => lng('serversettings.ssl.tlsv13_cipher_list.title'),
						'desc' => lng('serversettings.ssl.tlsv13_cipher_list.description').lng('admin.domain_override_tls_addinfo'),
						'type' => 'text',
						'value' => !empty($result['tlsv13_cipher_list']) ? $result['tlsv13_cipher_list'] : Settings::Get('system.tlsv13_cipher_list')
					],
					'ssl_specialsettings' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.ownsslvhostsettings'),
						'desc' => lng('serversettings.default_vhostconf.description'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12,
						'value' => $result['ssl_specialsettings']
					],
					'include_specialsettings' => [
						'visible' => !empty($ssl_ipsandports) && $userinfo['change_serversettings'] == '1',
						'label' => lng('serversettings.includedefault_sslvhostconf'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['include_specialsettings']
					],
					'hsts_maxage' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_hsts_maxage.title'),
						'desc' => lng('admin.domain_hsts_maxage.description'),
						'type' => 'number',
						'min' => 0,
						'max' => 94608000, // 3-years
						'value' => $result['hsts']
					],
					'hsts_sub' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_hsts_incsub.title'),
						'desc' => lng('admin.domain_hsts_incsub.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['hsts_sub']
					],
					'hsts_preload' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_hsts_preload.title'),
						'desc' => lng('admin.domain_hsts_preload.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['hsts_preload']
					],
					'ocsp_stapling' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_ocsp_stapling.title'),
						'desc' => lng('admin.domain_ocsp_stapling.description') . (Settings::Get('system.webserver') == 'nginx' ? lng('admin.domain_ocsp_stapling.nginx_version_warning') : ""),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['ocsp_stapling']
					],
					'honorcipherorder' => [
						'visible' => !empty($ssl_ipsandports),
						'label' => lng('admin.domain_honorcipherorder'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['ssl_honorcipherorder']
					],
					'sessiontickets' => [
						'visible' => !empty($ssl_ipsandports) && Settings::Get('system.sessionticketsenabled' != '1'),
						'label' => lng('admin.domain_sessiontickets'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['ssl_sessiontickets']
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
						'checked' => $result['openbasedir']
					],
					'openbasedir_path' => [
						'label' => lng('domain.openbasedirpath'),
						'type' => 'select',
						'select_var' => $openbasedir,
						'selected' => $result['openbasedir_path']
					],
					'phpenabled' => [
						'label' => lng('admin.phpenabled'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['phpenabled']
					],
					'phpsettingid' => [
						'visible' => (((int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1)),
						'label' => lng('admin.phpsettings.title'),
						'type' => 'select',
						'select_var' => $phpconfigs,
						'selected' => $result['phpsettingid']
					],
					'phpsettingsforsubdomains' => [
						'visible' => $userinfo['change_serversettings'] == '1',
						'label' => lng('admin.phpsettingsforsubdomains'),
						'desc' => lng('serversettings.phpsettingsforsubdomains.description'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => Settings::Get('system.apply_phpconfigs_default') == 1 ? '1' : '0'
					],
					'mod_fcgid_starter' => [
						'visible' => (int)Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.mod_fcgid_starter.title'),
						'type' => 'number',
						'value' => ((int)$result['mod_fcgid_starter'] != -1 ? $result['mod_fcgid_starter'] : '')
					],
					'mod_fcgid_maxrequests' => [
						'visible' => (int)Settings::Get('system.mod_fcgid') == 1,
						'label' => lng('admin.mod_fcgid_maxrequests.title'),
						'type' => 'number',
						'value' => ((int)$result['mod_fcgid_maxrequests'] != -1 ? $result['mod_fcgid_maxrequests'] : '')
					]
				]
			],
			'section_d' => [
				'title' => lng('admin.nameserversettings'),
				'visible' => ($userinfo['change_serversettings'] == '1' && Settings::Get('system.bind_enable') == '1') || ($result['isemaildomain'] == '1' && (Settings::Get('spf.use_spf') == '1' || Settings::Get('dmarc.use_dmarc') == '1') || Settings::Get('antispam.activated') == '1' && $result['dkim'] == '1' && $result['dkim_pubkey'] != ''),
				'fields' => [
					'isbinddomain' => [
						'visible' => $userinfo['change_serversettings'] == '1' && Settings::Get('system.bind_enable') == '1',
						'label' => lng('admin.createzonefile'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => $result['isbinddomain']
					],
					'zonefile' => [
						'visible' => $userinfo['change_serversettings'] == '1' && Settings::Get('system.bind_enable') == '1',
						'label' => lng('admin.custombindzone'),
						'desc' => lng('admin.bindzonewarning'),
						'type' => 'text',
						'value' => $result['zonefile']
					],
					'spf_entry' => [
						'visible' => (Settings::Get('spf.use_spf') == '1' && $result['isemaildomain'] == '1'),
						'label' => lng('antispam.required_spf_dns'),
						'type' => 'longtext',
						'value' => (string)(new \Froxlor\Dns\DnsEntry('@', 'TXT', \Froxlor\Dns\Dns::encloseTXTContent(Settings::Get('spf.spf_entry'))))
					],
					'dmarc_entry' => [
						'visible' => (Settings::Get('dmarc.use_dmarc') == '1' && $result['isemaildomain'] == '1'),
						'label' => lng('antispam.required_dmarc_dns'),
						'type' => 'longtext',
						'value' => (string)(new \Froxlor\Dns\DnsEntry('_dmarc', 'TXT', \Froxlor\Dns\Dns::encloseTXTContent(Settings::Get('dmarc.dmarc_entry'))))
					],
					'dkim_entry' => [
						'visible' => (Settings::Get('antispam.activated') == '1' && $result['dkim'] == '1' && $result['dkim_pubkey'] != ''),
						'label' => lng('antispam.required_dkim_dns'),
						'type' => 'longtext',
						'value' => (string)(new \Froxlor\Dns\DnsEntry('dkim' . $result['dkim_id'] . '._domainkey', 'TXT', \Froxlor\Dns\Dns::encloseTXTContent('v=DKIM1; k=rsa; p='.trim($result['dkim_pubkey']))))
					],
				]
			]
		]
	]
];
