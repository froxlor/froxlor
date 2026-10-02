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
	'groups' => [
		'webserver' => [
			'title' => lng('admin.webserversettings'),
			'icon' => 'fa-solid fa-server',
			'fields' => [
				'system_webserver' => [
					'label' => lng('admin.webserver'),
					'settinggroup' => 'system',
					'varname' => 'webserver',
					'type' => 'select',
					'default' => 'apache2',
					'select_var' => [
						'apache2' => 'Apache 2',
						'nginx' => 'Nginx'
					],
					'save_method' => 'storeSettingField',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkPhpInterfaceSetting'
					],
					'requires_reconf' => ['http']
				],
				'system_apache24' => [
					'label' => lng('serversettings.apache_24'),
					'settinggroup' => 'system',
					'varname' => 'apache24',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2'
					]
				],
				'system_apacheitksupport' => [
					'label' => lng('serversettings.apache_itksupport'),
					'settinggroup' => 'system',
					'varname' => 'apacheitksupport',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'visible' => (Settings::Get('system.mod_fcgid') == 0 && Settings::Get('phpfpm.enabled') == 0),
					'websrv_avail' => [
						'apache2'
					],
					'advanced_mode' => true
				],
				'system_http2_support' => [
					'label' => lng('serversettings.http2_support'),
					'settinggroup' => 'system',
					'varname' => 'http2_support',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2',
						'nginx'
					],
					'visible' => Settings::Get('system.use_ssl')
				],
				'system_http3_support' => [
					'label' => lng('serversettings.http3_support'),
					'settinggroup' => 'system',
					'varname' => 'http3_support',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'nginx'
					],
					'visible' => Settings::Get('system.use_ssl')
				],
				'system_dhparams_file' => [
					'label' => lng('serversettings.dhparams_file'),
					'settinggroup' => 'system',
					'varname' => 'dhparams_file',
					'type' => 'text',
					'string_type' => 'file',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField',
					'visible' => Settings::Get('system.use_ssl'),
					'advanced_mode' => true
				],
				'system_httpuser' => [
					'label' => lng('admin.webserver_user'),
					'settinggroup' => 'system',
					'varname' => 'httpuser',
					'type' => 'text',
					'default' => 'www-data',
					'plausibility_check_method' => [
						'\\Froxlor\\Validate\\Check',
						'checkSystemUsername'
					],
					'save_method' => 'storeSettingWebserverFcgidFpmUser'
				],
				'system_httpgroup' => [
					'label' => lng('admin.webserver_group'),
					'settinggroup' => 'system',
					'varname' => 'httpgroup',
					'type' => 'text',
					'default' => 'www-data',
					'save_method' => 'storeSettingField'
				],
				'system_apacheconf_vhost' => [
					'label' => lng('serversettings.apacheconf_vhost'),
					'settinggroup' => 'system',
					'varname' => 'apacheconf_vhost',
					'type' => 'text',
					'string_type' => 'filedir',
					'default' => '/etc/apache2/sites-enabled/',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http']
				],
				'system_apacheconf_diroptions' => [
					'label' => lng('serversettings.apacheconf_diroptions'),
					'settinggroup' => 'system',
					'varname' => 'apacheconf_diroptions',
					'type' => 'text',
					'string_type' => 'filedir',
					'default' => '/etc/apache2/sites-enabled/',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http']
				],
				'system_apacheconf_htpasswddir' => [
					'label' => lng('serversettings.apacheconf_htpasswddir'),
					'settinggroup' => 'system',
					'varname' => 'apacheconf_htpasswddir',
					'type' => 'text',
					'string_type' => 'confdir',
					'default' => '/etc/apache2/htpasswd/',
					'save_method' => 'storeSettingField'
				],
				'system_logfiles_directory' => [
					'label' => lng('serversettings.logfiles_directory'),
					'settinggroup' => 'system',
					'varname' => 'logfiles_directory',
					'type' => 'text',
					'string_type' => 'dir',
					'default' => '/var/customers/logs/',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http']
				],
				'system_logfiles_script' => [
					'label' => lng('serversettings.logfiles_script'),
					'settinggroup' => 'system',
					'varname' => 'logfiles_script',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2'
					],
					'advanced_mode' => true
				],
				'system_logfiles_piped' => [
					'label' => lng('serversettings.logfiles_piped'),
					'settinggroup' => 'system',
					'varname' => 'logfiles_piped',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2'
					],
					'advanced_mode' => true
				],
				'system_logfiles_format' => [
					'label' => lng('serversettings.logfiles_format'),
					'settinggroup' => 'system',
					'varname' => 'logfiles_format',
					'type' => (strpos(Settings::Get('system.logfiles_format'), '"') !== false ? 'textarea' : 'text'),
					'string_regexp' => '/^[^\0\r\n<>]*$/i',
					'default' => '',
					'string_emptyallowed' => true,
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2',
						'nginx'
					],
					'visible' => Settings::Get('system.traffictool') != 'webalizer',
					'advanced_mode' => true
				],
				'system_logfiles_type' => [
					'label' => lng('serversettings.logfiles_type'),
					'settinggroup' => 'system',
					'varname' => 'logfiles_type',
					'type' => 'select',
					'default' => '1',
					'select_var' => [
						'1' => 'combined',
						'2' => 'vhost_combined'
					],
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2'
					]
				],
				'system_errorlog_level' => [
					'label' => lng('serversettings.errorlog_level'),
					'settinggroup' => 'system',
					'varname' => 'errorlog_level',
					'type' => 'select',
					'default' => (Settings::Get('system.webserver') == 'nginx' ? 'error' : 'warn'),
					'select_var' => [
						'emerg' => 'emerg',
						'alert' => 'alert',
						'crit' => 'crit',
						'error' => 'error',
						'warn' => 'warn',
						'notice' => 'notice',
						'info' => 'info',
						'debug' => 'debug'
					],
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2',
						'nginx'
					]
				],
				'system_customer_ssl_path' => [
					'label' => lng('serversettings.customerssl_directory'),
					'settinggroup' => 'system',
					'varname' => 'customer_ssl_path',
					'type' => 'text',
					'string_type' => 'confdir',
					'default' => '/etc/ssl/froxlor-custom/',
					'save_method' => 'storeSettingField'
				],
				'system_phpappendopenbasedir' => [
					'label' => lng('serversettings.phpappendopenbasedir'),
					'settinggroup' => 'system',
					'varname' => 'phpappendopenbasedir',
					'type' => 'text',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_deactivateddocroot' => [
					'label' => lng('serversettings.deactivateddocroot'),
					'settinggroup' => 'system',
					'varname' => 'deactivateddocroot',
					'type' => 'text',
					'string_type' => 'dir',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http']
				],
				'system_default_vhostconf' => [
					'label' => lng('serversettings.default_vhostconf'),
					'settinggroup' => 'system',
					'varname' => 'default_vhostconf',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_default_sslvhostconf' => [
					'label' => lng('serversettings.default_sslvhostconf'),
					'settinggroup' => 'system',
					'varname' => 'default_sslvhostconf',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'visible' => Settings::Get('system.use_ssl') == 1,
					'advanced_mode' => true
				],
				'system_include_default_vhostconf' => [
					'label' => lng('serversettings.includedefault_sslvhostconf'),
					'settinggroup' => 'system',
					'varname' => 'include_default_vhostconf',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'system_apacheglobaldiropt' => [
					'label' => lng('serversettings.apache_globaldiropt'),
					'settinggroup' => 'system',
					'varname' => 'apacheglobaldiropt',
					'type' => 'textarea',
					'default' => '',
					'save_method' => 'storeSettingField',
					'visible' => (Settings::Get('system.mod_fcgid') == 0 && Settings::Get('phpfpm.enabled') == 0),
					'websrv_avail' => [
						'apache2'
					],
					'advanced_mode' => true
				],
				'system_apachereload_command' => [
					'label' => lng('serversettings.apachereload_command'),
					'settinggroup' => 'system',
					'varname' => 'apachereload_command',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => '/etc/init.d/apache2 reload',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'system_phpreload_command' => [
					'label' => lng('serversettings.phpreload_command'),
					'settinggroup' => 'system',
					'varname' => 'phpreload_command',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => '',
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'nginx'
					],
					'required_otp' => true
				],
				'system_nginx_php_backend' => [
					'label' => lng('serversettings.nginx_php_backend'),
					'settinggroup' => 'system',
					'varname' => 'nginx_php_backend',
					'type' => 'text',
					'default' => '127.0.0.1:8888',
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'nginx'
					]
				],
				'nginx_fastcgiparams' => [
					'label' => lng('serversettings.nginx_fastcgiparams'),
					'settinggroup' => 'nginx',
					'varname' => 'fastcgiparams',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/etc/nginx/fastcgi_params',
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'nginx'
					]
				],
				'defaultwebsrverrhandler_enabled' => [
					'label' => lng('serversettings.defaultwebsrverrhandler_enabled'),
					'settinggroup' => 'defaultwebsrverrhandler',
					'varname' => 'enabled',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'defaultwebsrverrhandler_err401' => [
					'label' => lng('serversettings.defaultwebsrverrhandler_err401'),
					'settinggroup' => 'defaultwebsrverrhandler',
					'varname' => 'err401',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2',
						'nginx'
					],
					'advanced_mode' => true
				],
				'defaultwebsrverrhandler_err403' => [
					'label' => lng('serversettings.defaultwebsrverrhandler_err403'),
					'settinggroup' => 'defaultwebsrverrhandler',
					'varname' => 'err403',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2',
						'nginx'
					],
					'advanced_mode' => true
				],
				'defaultwebsrverrhandler_err404' => [
					'label' => lng('serversettings.defaultwebsrverrhandler_err404'),
					'settinggroup' => 'defaultwebsrverrhandler',
					'varname' => 'err404',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'defaultwebsrverrhandler_err500' => [
					'label' => lng('serversettings.defaultwebsrverrhandler_err500'),
					'settinggroup' => 'defaultwebsrverrhandler',
					'varname' => 'err500',
					'type' => 'text',
					'default' => '',
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2',
						'nginx'
					],
					'advanced_mode' => true
				],
				'customredirect_enabled' => [
					'label' => lng('serversettings.customredirect_enabled'),
					'settinggroup' => 'customredirect',
					'varname' => 'enabled',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'customredirect_default' => [
					'label' => lng('serversettings.customredirect_default'),
					'settinggroup' => 'customredirect',
					'varname' => 'default',
					'type' => 'select',
					'default' => '1',
					'option_options_method' => ['\\Froxlor\\Domain\\Domain', 'getRedirectCodes'],
					'save_method' => 'storeSettingField'
				],
				'system_webserver_serveradmin' => [
					'label' => lng('admin.webserver_serveradmin.setting'),
					'settinggroup' => 'system',
					'varname' => 'webserver_serveradmin',
					'type' => 'select',
					'default' => 'customer',
					'select_var' => [
						'customer' => lng('admin.webserver_serveradmin.customer'),
						'admin' => lng('admin.webserver_serveradmin.admin'),
						'global' => lng('admin.webserver_serveradmin.global'),
						'none' => lng('admin.webserver_serveradmin.none')
					],
					'save_method' => 'storeSettingField',
					'websrv_avail' => [
						'apache2',
					],
				],
			]
		]
	]
];
