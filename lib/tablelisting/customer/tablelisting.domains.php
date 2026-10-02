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

use Froxlor\UI\Callbacks\Domain;
use Froxlor\UI\Callbacks\Style;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

return [
	'domain_list' => [
		'title' => lng('admin.domains'),
		'icon' => 'fa-solid fa-globe',
		'self_overview' => ['section' => 'domains', 'page' => 'domains'],
		'default_sorting' => ['d.domain_ace' => 'asc'],
		'columns' => [
			'd.domain_ace' => [
				'label' => lng('domains.domainname'),
				'field' => 'domain_ace',
				'callback' => [Domain::class, 'domainExternalLinkInfo'],
			],
			'ipsandports' => [
				'label' => lng('admin.ipsandports.ipsandports'),
				'field' => 'ipsandports',
				'sortable' => false,
				'callback' => [Domain::class, 'listIPs'],
				'searchable' => false,
			],
			'd.documentroot' => [
				'label' => lng('panel.path'),
				'field' => 'documentroot',
				'callback' => [Domain::class, 'domainTarget'],
			],
			'd.isbinddomain' => [
				'label' => lng('domains.isbinddomain'),
				'field' => 'isbinddomain',
				'callback' => [Text::class, 'boolean'],
			],
			'd.isemaildomain' => [
				'label' => lng('admin.emaildomain'),
				'field' => 'isemaildomain',
				'callback' => [Text::class, 'boolean'],
			],
			'd.email_only' => [
				'label' => lng('admin.email_only'),
				'field' => 'email_only',
				'callback' => [Text::class, 'boolean'],
			],
			'd.iswildcarddomain' => [
				'label' => lng('domains.serveraliasoption_wildcard'),
				'field' => 'iswildcarddomain',
				'callback' => [Text::class, 'boolean'],
			],
			'd.letsencrypt' => [
				'label' => lng('panel.letsencrypt'),
				'field' => 'letsencrypt',
				'callback' => [Text::class, 'boolean'],
			],
			'ad.id' => [
				'label' => lng('domains.aliasdomainid'),
				'field' => 'aliasdomainid'
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('domain_list', [
			'd.domain_ace',
			'd.documentroot'
		]),
		'actions' => [
			'edit' => [
				'icon' => 'fa-solid fa-edit',
				'title' => lng('panel.edit'),
				'href' => [
					'section' => 'domains',
					'page' => 'domains',
					'action' => 'edit',
					'id' => ':id'
				],
				'visible' => [Domain::class, 'canEdit']
			],
			'logfiles' => [
				'icon' => 'fa-solid fa-file',
				'title' => lng('panel.viewlogs'),
				'href' => [
					'section' => 'domains',
					'page' => 'logfiles',
					'domain_id' => ':id'
				],
				'visible' => [Domain::class, 'canViewLogs']
			],
			'domaindnseditor' => [
				'icon' => 'fa-solid fa-globe',
				'title' => lng('dnseditor.edit'),
				'href' => [
					'section' => 'domains',
					'page' => 'domaindnseditor',
					'domain_id' => ':id'
				],
				'visible' => [Domain::class, 'canEditDNS']
			],
			'domainssleditor' => [
				'callback' => [Domain::class, 'editSSLButtons'],
			],
			'letsencrypt' => [
				'icon' => 'fa-solid fa-shield',
				'title' => lng('panel.letsencrypt'),
				'visible' => [Domain::class, 'hasLetsEncryptActivated']
			],
			'haslias' => [
				'icon' => 'fa-solid fa-arrow-up-right-from-square',
				'title' => lng('domains.hasaliasdomains'),
				'href' => [
					'section' => 'domains',
					'page' => 'domains',
					'searchfield' => 'ad.id',
					'searchtext' => ':id'
				],
				'visible' => [Domain::class, 'canEditAlias']
			],
			'isassigned' => [
				'icon' => 'fa-solid fa-check-to-slot',
				'title' => lng('domains.isassigneddomain'),
				'visible' => [Domain::class, 'isAssigned']
			],
			'delete' => [
				'icon' => 'fa-solid fa-trash',
				'title' => lng('panel.delete'),
				'class' => 'btn-danger',
				'href' => [
					'section' => 'domains',
					'page' => 'domains',
					'action' => 'delete',
					'id' => ':id'
				],
				'visible' => [Domain::class, 'canDelete']
			]
		],
		'format_callback' => [
			[Style::class, 'resultDomainTerminatedOrDeactivated']
		]
	]
];
