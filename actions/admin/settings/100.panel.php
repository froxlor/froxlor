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
	'groups' => [
		'panel' => [
			'title' => lng('admin.panelsettings'),
			'icon' => 'fa-solid fa-chalkboard-user',
			'fields' => [
				'panel_standardlanguage' => [
					'label' => [
						'title' => lng('login.language'),
						'description' => lng('serversettings.language.description')
					],
					'settinggroup' => 'panel',
					'varname' => 'standardlanguage',
					'type' => 'select',
					'default' => 'en',
					'option_options_method' => [
						'\\Froxlor\\Language',
						'getLanguages'
					],
					'save_method' => 'storeSettingField'
				],
				'panel_default_theme' => [
					'label' => [
						'title' => lng('panel.theme'),
						'description' => lng('serversettings.default_theme')
					],
					'settinggroup' => 'panel',
					'varname' => 'default_theme',
					'type' => 'select',
					'default' => 'Froxlor',
					'option_options_method' => [
						'\\Froxlor\\UI\\Panel\\UI',
						'getThemes'
					],
					'save_method' => 'storeSettingDefaultTheme'
				],
				'panel_allow_theme_change_customer' => [
					'label' => lng('serversettings.panel_allow_theme_change_customer'),
					'settinggroup' => 'panel',
					'varname' => 'allow_theme_change_customer',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'panel_allow_theme_change_admin' => [
					'label' => lng('serversettings.panel_allow_theme_change_admin'),
					'settinggroup' => 'panel',
					'varname' => 'allow_theme_change_admin',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField'
				],
				'panel_natsorting' => [
					'label' => lng('serversettings.natsorting'),
					'settinggroup' => 'panel',
					'varname' => 'natsorting',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_paging' => [
					'label' => lng('serversettings.paging'),
					'settinggroup' => 'panel',
					'varname' => 'paging',
					'type' => 'number',
					'min' => 0,
					'default' => 0,
					'save_method' => 'storeSettingField'
				],
				'panel_pathedit' => [
					'label' => lng('serversettings.pathedit'),
					'settinggroup' => 'panel',
					'varname' => 'pathedit',
					'type' => 'select',
					'default' => 'Manual',
					'select_var' => [
						'Manual' => lng('serversettings.manual'),
						'Dropdown' => lng('serversettings.dropdown')
					],
					'save_method' => 'storeSettingField'
				],
				'panel_adminmail' => [
					'label' => lng('serversettings.adminmail'),
					'settinggroup' => 'panel',
					'varname' => 'adminmail',
					'type' => 'email',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'panel_adminmail_defname' => [
					'label' => lng('serversettings.adminmail_defname'),
					'settinggroup' => 'panel',
					'varname' => 'adminmail_defname',
					'type' => 'text',
					'default' => 'Froxlor Administrator',
					'save_method' => 'storeSettingField'
				],
				'panel_adminmail_return' => [
					'label' => lng('serversettings.adminmail_return'),
					'settinggroup' => 'panel',
					'varname' => 'adminmail_return',
					'type' => 'email',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_decimal_places' => [
					'label' => lng('serversettings.decimal_places'),
					'settinggroup' => 'panel',
					'varname' => 'decimal_places',
					'type' => 'number',
					'min' => 0,
					'max' => 15,
					'default' => 4,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_phpmyadmin_url' => [
					'label' => lng('serversettings.phpmyadmin_url'),
					'settinggroup' => 'panel',
					'varname' => 'phpmyadmin_url',
					'type' => 'url',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'panel_webmail_url' => [
					'label' => lng('serversettings.webmail_url'),
					'settinggroup' => 'panel',
					'varname' => 'webmail_url',
					'type' => 'url',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'panel_webftp_url' => [
					'label' => lng('serversettings.webftp_url'),
					'settinggroup' => 'panel',
					'varname' => 'webftp_url',
					'type' => 'url',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'admin_show_version_login' => [
					'label' => lng('admin.show_version_login'),
					'settinggroup' => 'admin',
					'varname' => 'show_version_login',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'admin_show_version_footer' => [
					'label' => lng('admin.show_version_footer'),
					'settinggroup' => 'admin',
					'varname' => 'show_version_footer',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'admin_show_news_feed' => [
					'label' => lng('admin.show_news_feed'),
					'settinggroup' => 'admin',
					'varname' => 'show_news_feed',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'customer_show_news_feed' => [
					'label' => lng('admin.customer_show_news_feed'),
					'settinggroup' => 'customer',
					'varname' => 'show_news_feed',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'customer_news_feed_url' => [
					'label' => lng('admin.customer_news_feed_url'),
					'settinggroup' => 'customer',
					'varname' => 'news_feed_url',
					'type' => 'url',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'panel_allow_domain_change_admin' => [
					'label' => lng('serversettings.panel_allow_domain_change_admin'),
					'settinggroup' => 'panel',
					'varname' => 'allow_domain_change_admin',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_allow_domain_change_customer' => [
					'label' => lng('serversettings.panel_allow_domain_change_customer'),
					'settinggroup' => 'panel',
					'varname' => 'allow_domain_change_customer',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_phpconfigs_hidesubdomains' => [
					'label' => lng('serversettings.panel_phpconfigs_hidesubdomains'),
					'settinggroup' => 'panel',
					'varname' => 'phpconfigs_hidesubdomains',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_phpconfigs_hidestdsubdomain' => [
					'label' => lng('serversettings.panel_phpconfigs_hidestdsubdomain'),
					'settinggroup' => 'panel',
					'varname' => 'phpconfigs_hidestdsubdomain',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_customer_hide_options' => [
					'label' => lng('serversettings.panel_customer_hide_options'),
					'settinggroup' => 'panel',
					'varname' => 'customer_hide_options',
					'type' => 'select',
					'default' => '',
					'select_mode' => 'multiple',
					'option_emptyallowed' => true,
					'select_var' => [
						'email' => lng('menue.email.email'),
						'mysql' => lng('menue.mysql.mysql'),
						'domains' => lng('menue.domains.domains'),
						'ftp' => lng('menue.ftp.ftp'),
						'extras' => lng('menue.extras.extras'),
						'extras.directoryprotection' => lng('menue.extras.extras') . " / " . lng('menue.extras.directoryprotection'),
						'extras.pathoptions' => lng('menue.extras.extras') . " / " . lng('menue.extras.pathoptions'),
						'extras.logger' => lng('menue.extras.extras') . " / " . lng('menue.logger.logger'),
						'extras.export' => lng('menue.extras.extras') . " / " . lng('menue.extras.export'),
						'traffic' => lng('menue.traffic.traffic'),
						'traffic.http' => lng('menue.traffic.traffic') . " / HTTP",
						'traffic.ftp' => lng('menue.traffic.traffic') . " / FTP",
						'traffic.mail' => lng('menue.traffic.traffic') . " / Mail",
						'misc.documentation' => lng('admin.documentation'),
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'panel_imprint_url' => [
					'label' => lng('serversettings.imprint_url'),
					'settinggroup' => 'panel',
					'varname' => 'imprint_url',
					'type' => 'url',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'panel_terms_url' => [
					'label' => lng('serversettings.terms_url'),
					'settinggroup' => 'panel',
					'varname' => 'terms_url',
					'type' => 'url',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'panel_privacy_url' => [
					'label' => lng('serversettings.privacy_url'),
					'settinggroup' => 'panel',
					'varname' => 'privacy_url',
					'type' => 'url',
					'string_emptyallowed' => true,
					'default' => '',
					'save_method' => 'storeSettingField'
				],
				'panel_logo_overridetheme' => [
					'label' => lng('serversettings.logo_overridetheme'),
					'settinggroup' => 'panel',
					'varname' => 'logo_overridetheme',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'panel_logo_overridecustom' => [
					'label' => lng('serversettings.logo_overridecustom'),
					'settinggroup' => 'panel',
					'varname' => 'logo_overridecustom',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField'
				],
				'panel_logo_image_header' => [
					'label' => lng('serversettings.logo_image_header'),
					'settinggroup' => 'panel',
					'varname' => 'logo_image_header',
					'type' => 'image',
					'accept' => 'image/jpeg, image/jpg, image/png, image/gif',
					'image_name' => 'logo_header',
					'default' => '',
					'save_method' => 'storeSettingImage'
				],
				'panel_logo_image_login' => [
					'label' => lng('serversettings.logo_image_login'),
					'settinggroup' => 'panel',
					'varname' => 'logo_image_login',
					'type' => 'image',
					'accept' => 'image/jpeg, image/jpg, image/png, image/gif',
					'image_name' => 'logo_login',
					'default' => '',
					'save_method' => 'storeSettingImage'
				],
				'panel_menu_collapsed' => [
					'label' => lng('serversettings.panel_menu_collapsed'),
					'settinggroup' => 'panel',
					'varname' => 'menu_collapsed',
					'type' => 'checkbox',
					'default' => true,
					'save_method' => 'storeSettingField',
				],
			]
		]
	]
];
