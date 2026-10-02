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
	'emails_edit' => [
		'title' => lng('emails.emails_edit'),
		'image' => 'fa-solid fa-pen',
		'self_overview' => ['section' => 'email', 'page' => 'email_domain', 'domainid' => $result['domainid']],
		'sections' => [
			'section_a' => [
				'title' => lng('emails.emails_edit'),
				'fields' => [
					'email_full' => [
						'label' => lng('emails.emailaddress'),
						'type' => 'label',
						'value' => $result['email_full']
					],
					'account_yes' => [
						'visible' => (int)$result['popaccountid'] != 0,
						'label' => lng('emails.account'),
						'type' => 'label',
						'value' => lng('panel.yes'),
						'next_to' => [
							'edit_link' => [
								'type' => 'link',
								'href' => $filename . '?page=accounts&amp;domainid=' . $result['domainid'] . '&amp;action=changepw&amp;id=' . $result['id'],
								'label' => lng('menue.main.changepassword'),
								'classes' => 'btn btn-sm btn-secondary'
							],
							'del_link' => [
								'type' => 'link',
								'href' => $filename . '?page=accounts&amp;domainid=' . $result['domainid'] . '&amp;action=delete&amp;id=' . $result['id'],
								'label' => lng('emails.account_delete'),
								'classes' => 'btn btn-sm btn-danger'
							]
						]
					],
					'account_no' => [
						'visible' => (int)$result['popaccountid'] == 0,
						'label' => lng('emails.account'),
						'type' => 'label',
						'value' => lng('panel.no'),
						'next_to' => [
							'add_link' => [
								'type' => 'link',
								'href' => $filename . '?page=accounts&amp;domainid=' . $result['domainid'] . '&amp;action=add&amp;id=' . $result['id'],
								'label' => lng('emails.account_add'),
								'classes' => 'btn btn-sm btn-primary'
							]
						]
					],
					'mail_quota' => [
						'visible' => ((int)$result['popaccountid'] != 0 && Settings::Get('system.mail_quota_enabled')),
						'label' => lng('customer.email_quota'),
						'type' => 'label',
						'value' => $result['quota'] . ' MiB',
						'next_to' => [
							'add_link' => [
								'visible' => ((int)$result['popaccountid'] != 0 && Settings::Get('system.mail_quota_enabled')),
								'type' => 'link',
								'href' => $filename . '?page=accounts&amp;domainid=' . $result['domainid'] . '&amp;action=changequota&amp;id=' . $result['id'],
								'label' => lng('emails.quota_edit'),
								'classes' => 'btn btn-sm btn-secondary'
							]
						]
					],
					'iscatchall' => [
						'visible' => Settings::Get('catchall.catchall_enabled') == '1',
						'label' => lng('emails.catchall'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => (int)$result['iscatchall'],
					],
					'bypass_spam' => [
						'visible' => Settings::Get('antispam.activated') == '1' && (int)Settings::Get('antispam.default_bypass_spam') <= 2,
						'label' => lng('antispam.bypass_spam'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => (int)$result['bypass_spam'],
					],
					'spam_tag_level' => [
						'visible' => Settings::Get('antispam.activated') == '1',
						'label' => lng('antispam.spam_tag_level'),
						'type' => 'number',
						'min' => 0,
						'step' => 0.1,
						'value' => $result['spam_tag_level'],
					],
					'rewrite_subject' => [
						'visible' => Settings::Get('antispam.activated') == '1' && (int)Settings::Get('antispam.default_spam_rewrite_subject') <= 2,
						'label' => lng('antispam.rewrite_subject'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => (int)$result['rewrite_subject'],
					],
					'spam_kill_level' => [
						'visible' => Settings::Get('antispam.activated') == '1',
						'label' => lng('antispam.spam_kill_level'),
						'desc' => lng('panel.use_checkbox_to_disable'),
						'type' => 'textul',
						'step' => 0.1,
						'value' => $result['spam_kill_level']
					],
					'policy_greylist' => [
						'visible' => Settings::Get('antispam.activated') == '1' && (int)Settings::Get('antispam.default_policy_greylist') <= 2,
						'label' => lng('antispam.policy_greylist'),
						'type' => 'checkbox',
						'value' => '1',
						'checked' => (int)$result['policy_greylist'],
					],
					'mail_fwds' => [
						'label' => lng('emails.forwarders') . ' (' . $forwarders_count . ')',
						'type' => 'itemlist',
						'values' => $forwarders,
						'next_to' => [
							'add_link' => [
								'type' => 'link',
								'href' => $filename . '?page=forwarders&amp;domainid=' . $result['domainid'] . '&amp;action=add&amp;id=' . $result['id'],
								'label' => lng('emails.forwarder_add'),
								'classes' => 'btn btn-sm btn-primary'
							]
						]
					],
					'mail_senders' => [
						'visible' => ((int)$result['popaccountid'] != 0 && Settings::Get('mail.enable_allow_sender') == '1'),
						'label' => lng('emails.senders') . ' (' . $senders_count . ')',
						'type' => 'itemlist',
						'values' => $senders,
						'next_to' => [
							'add_link' => [
								'type' => 'link',
								'href' => $filename . '?page=senders&amp;domainid=' . $result['domainid'] . '&amp;action=add&amp;id=' . $result['id'],
								'label' => lng('emails.sender_add'),
								'classes' => 'btn btn-sm btn-primary'
							]
						]
					]
				]
			]
		],
		'buttons' => [
			[
				'label' => lng('panel.save')
			]
		]
	]
];
