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

use Froxlor\Froxlor;
use Froxlor\Settings;

return [
	'groups' => [
		'ssl' => [
			'title' => lng('admin.sslsettings'),
			'icon' => 'fa-solid fa-shield',
			'fields' => [
				'system_use_ssl' => [
					'label' => lng('serversettings.ssl.use_ssl'),
					'settinggroup' => 'system',
					'varname' => 'use_ssl',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'overview_option' => true,
					'requires_reconf' => ['http']
				],
				'system_ssl_protocols' => [
					'label' => lng('serversettings.ssl.ssl_protocols'),
					'settinggroup' => 'system',
					'varname' => 'ssl_protocols',
					'type' => 'select',
					'default' => 'TLSv1.2',
					'select_mode' => 'multiple',
					'select_var' => [
						'TLSv1' => 'TLSv1',
						'TLSv1.1' => 'TLSv1.1',
						'TLSv1.2' => 'TLSv1.2',
						'TLSv1.3' => 'TLSv1.3'
					],
					'save_method' => 'storeSettingField'
				],
				'system_ssl_cipher_list' => [
					'label' => lng('serversettings.ssl.ssl_cipher_list'),
					'settinggroup' => 'system',
					'varname' => 'ssl_cipher_list',
					'type' => 'text',
					'string_emptyallowed' => false,
					'default' => 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_tlsv13_cipher_list' => [
					'label' => lng('serversettings.ssl.tlsv13_cipher_list'),
					'settinggroup' => 'system',
					'varname' => 'tlsv13_cipher_list',
					'type' => 'text',
					'string_emptyallowed' => true,
					'default' => '',
					'visible' => Settings::Get('system.webserver') == "apache2" && Settings::Get('system.apache24') == 1,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_ssl_cert_file' => [
					'label' => lng('serversettings.ssl.ssl_cert_file'),
					'settinggroup' => 'system',
					'varname' => 'ssl_cert_file',
					'type' => 'text',
					'string_type' => 'file',
					'string_emptyallowed' => true,
					'default' => '/etc/ssl/froxlor_selfsigned.pem',
					'save_method' => 'storeSettingField'
				],
				'system_ssl_key_file' => [
					'label' => lng('serversettings.ssl.ssl_key_file'),
					'settinggroup' => 'system',
					'varname' => 'ssl_key_file',
					'type' => 'text',
					'string_type' => 'file',
					'string_emptyallowed' => true,
					'default' => '/etc/ssl/froxlor_selfsigned.key',
					'save_method' => 'storeSettingField'
				],
				'system_ssl_cert_chainfile' => [
					'label' => lng('admin.ipsandports.ssl_cert_chainfile'),
					'settinggroup' => 'system',
					'varname' => 'ssl_cert_chainfile',
					'type' => 'text',
					'string_type' => 'file',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'system_ssl_ca_file' => [
					'label' => lng('serversettings.ssl.ssl_ca_file'),
					'settinggroup' => 'system',
					'varname' => 'ssl_ca_file',
					'type' => 'text',
					'string_type' => 'file',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'system_apache24_ocsp_cache_path' => [
					'label' => lng('serversettings.ssl.apache24_ocsp_cache_path'),
					'settinggroup' => 'system',
					'varname' => 'apache24_ocsp_cache_path',
					'type' => 'text',
					'string_emptyallowed' => false,
					'default' => 'shmcb:/var/run/apache2/ocsp-stapling.cache(131072)',
					'visible' => Settings::Get('system.webserver') == "apache2" && Settings::Get('system.apache24') == 1,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_sessionticketsenabled' => [
					'label' => lng('admin.domain_sessionticketsenabled'),
					'settinggroup' => 'system',
					'varname' => 'sessionticketsenabled',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'visible' => Settings::Get('system.use_ssl') && (Settings::Get('system.webserver') == "nginx" || (Settings::Get('system.webserver') == "apache2" && Settings::Get('system.apache24') == 1)),
					'advanced_mode' => true
				],
				'system_leenabled' => [
					'label' => lng('serversettings.leenabled'),
					'settinggroup' => 'system',
					'varname' => 'leenabled',
					'type' => 'checkbox',
					'default' => false,
					'cronmodule' => 'froxlor/letsencrypt',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http']
				],
				'system_acmeshpath' => [
					'label' => lng('serversettings.acmeshpath'),
					'settinggroup' => 'system',
					'varname' => 'acmeshpath',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/root/.acme.sh/acme.sh',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'required_otp' => true
				],
				'system_letsencryptacmeconf' => [
					'label' => lng('serversettings.letsencryptacmeconf'),
					'settinggroup' => 'system',
					'varname' => 'letsencryptacmeconf',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/etc/apache2/conf-enabled/acme.conf',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http']
				],
				'system_letsencryptca' => [
					'label' => lng('serversettings.letsencryptca'),
					'settinggroup' => 'system',
					'varname' => 'letsencryptca',
					'type' => 'select',
					'default' => 'letsencrypt',
					'select_var' => [
						'letsencrypt_test' => 'Let\'s Encrypt (Test / Staging)',
						'letsencrypt' => 'Let\'s Encrypt (Live)',
						'buypass_test' => 'Buypass (Test / Staging)',
						'buypass' => 'Buypass (Live)',
						'zerossl' => 'ZeroSSL (Live)',
						'google' => 'Google (Live)',
						'google_test' => 'Google (Test / Staging)',
					],
					'save_method' => 'storeSettingField'
				],
				'system_letsencryptchallengepath' => [
					'label' => lng('serversettings.letsencryptchallengepath'),
					'settinggroup' => 'system',
					'varname' => 'letsencryptchallengepath',
					'type' => 'text',
					'string_type' => 'dir',
					'string_emptyallowed' => false,
					'default' => Froxlor::getInstallDir(),
					'save_method' => 'storeSettingField',
					'advanced_mode' => true,
					'requires_reconf' => ['http'],
					'required_otp' => true
				],
				'system_letsencryptkeysize' => [
					'label' => lng('serversettings.letsencryptkeysize'),
					'settinggroup' => 'system',
					'varname' => 'letsencryptkeysize',
					'type' => 'select',
					'default' => '2048',
					'select_var' => [
						'2048' => '2048',
						'3072' => '3072',
						'4096' => '4096',
						'8192' => '8192'
					],
					'save_method' => 'storeSettingField'
				],
				'system_leecc' => [
					'label' => lng('serversettings.letsencryptecc'),
					'settinggroup' => 'system',
					'varname' => 'leecc',
					'type' => 'select',
					'default' => '0',
					'select_var' => [
						'0' => '-',
						'256' => 'ec-256',
						'384' => 'ec-384'
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_letsencryptreuseold' => [
					'label' => lng('serversettings.letsencryptreuseold'),
					'settinggroup' => 'system',
					'varname' => 'letsencryptreuseold',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_le_domain_dnscheck' => [
					'label' => lng('serversettings.le_domain_dnscheck'),
					'settinggroup' => 'system',
					'varname' => 'le_domain_dnscheck',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'system_le_domain_dnscheck_resolver' => [
					'label' => lng('serversettings.le_domain_dnscheck_resolver'),
					'settinggroup' => 'system',
					'varname' => 'le_domain_dnscheck_resolver',
					'type' => 'text',
					'string_type' => 'validate_ip',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_le_renew_services' => [
					'label' => lng('serversettings.le_renew_services'),
					'settinggroup' => 'system',
					'varname' => 'le_renew_services',
					'type' => 'select',
					'default' => '',
					'select_mode' => 'multiple',
					'option_emptyallowed' => true,
					'select_var' => [
						'' => lng('panel.none_value'),
						'postfix' => 'postfix (smtp)',
						'dovecot' => 'dovecot <2.4 (imap/pop3)',
						'dovecot24' => 'dovecot >=2.4 (imap/pop3)',
						'proftpd' => 'proftpd (ftp)',
					],
					'save_method' => 'storeSettingFieldInsertUpdateServicesTask',
					'advanced_mode' => true
				],
				'system_le_renew_hook' => [
					'label' => lng('serversettings.le_renew_hook'),
					'settinggroup' => 'system',
					'varname' => 'le_renew_hook',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => 'systemctl restart postfix dovecot proftpd',
					'save_method' => 'storeSettingFieldInsertUpdateServicesTask',
					'advanced_mode' => true,
					'required_otp' => true
				],
			]
		]
	]
];
