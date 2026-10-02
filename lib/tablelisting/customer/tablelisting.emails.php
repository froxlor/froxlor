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
use Froxlor\UI\Callbacks\Email;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'email_list' => [
		'title' => lng('menue.email.emails'),
		'icon' => 'fa-solid fa-envelope',
		'self_overview' => ['section' => 'email', 'page' => 'email_domain'],
		'default_sorting' => ['m.email_full' => 'asc'],
		'columns' => [
			'm.email_full' => [
				'label' => lng('emails.emailaddress'),
				'field' => 'email_full',
			],
			'm.destination' => [
				'label' => lng('emails.forwarders'),
				'field' => 'destination',
				'callback' => [Email::class, 'forwarderList'],
			],
			'm.popaccountid' => [
				'label' => lng('emails.account'),
				'field' => 'popaccountid',
				'callback' => [Email::class, 'account'],
			],
			'm.spam_tag_level' => [
				'label' => lng('antispam.spam_tag_level.title'),
				'field' => 'spam_tag_level',
			],
			'm.spam_kill_level' => [
				'label' => lng('antispam.spam_kill_level.title'),
				'field' => 'spam_kill_level',
			],
			'm.bypass_spam' => [
				'label' => lng('antispam.bypass_spam.title'),
				'field' => 'bypass_spam',
				'callback' => [Text::class, 'boolean'],
			],
			'm.policy_greylist' => [
				'label' => lng('antispam.policy_greylist.title'),
				'field' => 'policy_greylist',
				'callback' => [Text::class, 'boolean'],
			],
			'm.iscatchall' => [
				'label' => lng('emails.catchall'),
				'field' => 'iscatchall',
				'callback' => [Text::class, 'boolean'],
				'visible' => Settings::Get('catchall.catchall_enabled') == '1'
			],
			'u.quota' => [
				'label' => lng('emails.quota'),
				'field' => 'quota',
				'visible' => Settings::Get('system.mail_quota_enabled') == '1'
			]
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('email_list', [
			'm.email_full',
			'm.destination',
			'm.popaccountid',
			'm.iscatchall',
			'u.quota'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'email',
					'page' => 'email_domain',
					'domainid' => ':domainid',
					'action' => 'edit',
					'id' => ':id'
				],
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'email',
					'page' => 'email_domain',
					'domainid' => ':domainid',
					'action' => 'delete',
					'id' => ':id'
				],
			]
		]
	]
];
