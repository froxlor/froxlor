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
		'antispam' => [
			'title' => lng('admin.antispam_settings'),
			'icon' => 'fa-solid fa-clipboard-check',
			'fields' => [
				'antispam_activated' => [
					'label' => lng('antispam.activated'),
					'settinggroup' => 'antispam',
					'varname' => 'activated',
					'type' => 'checkbox',
					'default' => true,
					'overview_option' => true,
					'save_method' => 'storeSettingFieldInsertAntispamTask',
				],
				'antispam_config_file' => [
					'label' => lng('antispam.config_file'),
					'settinggroup' => 'antispam',
					'varname' => 'config_file',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/etc/rspamd/local.d/froxlor_settings.conf',
					'save_method' => 'storeSettingFieldInsertAntispamTask',
					'requires_reconf' => ['antispam']
				],
				'antispam_reload_command' => [
					'label' => lng('antispam.reload_command'),
					'settinggroup' => 'antispam',
					'varname' => 'reload_command',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => 'service rspamd restart',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'antispam_default_bypass_spam' => [
					'label' => lng('antispam.default_bypass_spam'),
					'settinggroup' => 'antispam',
					'varname' => 'default_bypass_spam',
					'type' => 'select',
					'default' => 2,
					'select_var' => [
						1 => lng('antispam.default_select.on_changeable'),
						2 => lng('antispam.default_select.off_changeable'),
						3 => lng('antispam.default_select.on_unchangeable'),
						4 => lng('antispam.default_select.off_unchangeable'),
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'antispam_default_spam_rewrite_subject' => [
					'label' => lng('antispam.default_spam_rewrite_subject'),
					'settinggroup' => 'antispam',
					'varname' => 'default_spam_rewrite_subject',
					'type' => 'select',
					'default' => 1,
					'select_var' => [
						1 => lng('antispam.default_select.on_changeable'),
						2 => lng('antispam.default_select.off_changeable'),
						3 => lng('antispam.default_select.on_unchangeable'),
						4 => lng('antispam.default_select.off_unchangeable'),
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'antispam_default_policy_greylist' => [
					'label' => lng('antispam.default_policy_greylist'),
					'settinggroup' => 'antispam',
					'varname' => 'default_policy_greylist',
					'type' => 'select',
					'default' => 1,
					'select_var' => [
						1 => lng('antispam.default_select.on_changeable'),
						2 => lng('antispam.default_select.off_changeable'),
						3 => lng('antispam.default_select.on_unchangeable'),
						4 => lng('antispam.default_select.off_unchangeable'),
					],
					'save_method' => 'storeSettingField',
					'advanced_mode' => true
				],
				'antispam_dkim_keylength' => [
					'label' => lng('antispam.dkim_keylength'),
					'settinggroup' => 'antispam',
					'varname' => 'dkim_keylength',
					'type' => 'select',
					'default' => '1024',
					'select_var' => [
						'1024' => '1024 Bit',
						'2048' => '2048 Bit'
					],
					'save_method' => 'storeSettingFieldInsertBindTask',
					'advanced_mode' => true,
				],
				'spf_use_spf' => [
					'label' => lng('spf.use_spf'),
					'settinggroup' => 'spf',
					'varname' => 'use_spf',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
				],
				'spf_spf_entry' => [
					'label' => lng('spf.spf_entry'),
					'settinggroup' => 'spf',
					'varname' => 'spf_entry',
					'type' => 'text',
					'string_regexp' => '/^v=spf[a-z0-9:~?\s\.\-\/]+$/i',
					'default' => 'v=spf1 a mx -all',
					'save_method' => 'storeSettingField'
				],
				'dmarc_use_dmarc' => [
					'label' => lng('dmarc.use_dmarc'),
					'settinggroup' => 'dmarc',
					'varname' => 'use_dmarc',
					'type' => 'checkbox',
					'default' => false,
					'save_method' => 'storeSettingField',
				],
				'dmarc_dmarc_entry' => [
					'label' => lng('dmarc.dmarc_entry'),
					'settinggroup' => 'dmarc',
					'varname' => 'dmarc_entry',
					'type' => 'text',
					'string_regexp' => '/^v=dmarc1(.+)$/i',
					'default' => 'v=DMARC1; p=none;',
					'save_method' => 'storeSettingField'
				]
			]
		]
	]
];
