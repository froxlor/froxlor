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
use Froxlor\UI\Callbacks\Domain;
use Froxlor\UI\Callbacks\Impersonate;
use Froxlor\UI\Callbacks\Style;
use Froxlor\UI\Callbacks\Text;
use Froxlor\UI\Listing;

// used outside scope variables
$customerCollectionCount = !is_null($customerCollection ?? null) ? $customerCollection->count() : 0;

return [
	'domain_list' => [
		'title' => lng('admin.domains'),
		'icon' => 'fa-solid fa-globe',
		'empty_msg' => $customerCollectionCount == 0 ? lng('admin.domain_nocustomeraddingavailable') : '',
		'self_overview' => ['section' => 'domains', 'page' => 'domains'],
		'default_sorting' => ['d.domain_ace' => 'asc'],
		'columns' => [
			'd.id' => [
				'label' => 'ID',
				'field' => 'id',
				'sortable' => true,
			],
			'd.domain_ace' => [
				'label' => lng('domains.domainname'),
				'field' => 'domain_ace',
				'isdefaultsearchfield' => true,
				'callback' => [Domain::class, 'domainEditLink'],
			],
			'ipsandports' => [
				'label' => lng('admin.ipsandports.ipsandports'),
				'field' => 'ipsandports',
				'sortable' => false,
				'callback' => [Domain::class, 'listIPs'],
			],
			'c.name' => [
				'label' => lng('customer.name'),
				'field' => 'customer.name',
				'callback' => [Text::class, 'customerfullname'],
			],
			'c.loginname' => [
				'label' => lng('login.username'),
				'field' => 'customer.loginname',
				'callback' => [Impersonate::class, 'customer'],
			],
			'd.aliasdomain' => [
				'label' => lng('domains.aliasdomain'),
				'field' => 'aliasdomain',
			],
			'd.documentroot' => [
				'label' => lng('customer.documentroot'),
				'field' => 'documentroot',
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
			'd.subcanemaildomain' => [
				'label' => lng('admin.subdomainforemail'),
				'field' => 'subcanemaildomain',
				'callback' => [Text::class, 'boolean'],
			],
			'd.caneditdomain' => [
				'label' => lng('admin.domain_editable.title'),
				'field' => 'caneditdomain',
				'callback' => [Text::class, 'boolean'],
			],
			'd.dkim' => [
				'label' => lng('domains.dkimenabled'),
				'field' => 'dkim',
				'callback' => [Text::class, 'boolean'],
			],
			'd.phpenabled' => [
				'label' => lng('admin.phpenabled'),
				'field' => 'phpenabled',
				'callback' => [Text::class, 'boolean'],
			],
			'd.phpsettingid' => [
				'label' => lng('admin.phpsettings.title'),
				'field' => 'phpsettingid',
				'searchable' => false,
				'callback' => [Domain::class, 'getPhpConfigName'],
				'visible' => (int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1
			],
			'd.openbasedir' => [
				'label' => lng('domains.openbasedirenabled'),
				'field' => 'openbasedir',
				'callback' => [Text::class, 'boolean'],
			],
			'd.speciallogfile' => [
				'label' => lng('admin.speciallogfile.title'),
				'field' => 'speciallogfile',
				'callback' => [Text::class, 'boolean'],
			],
			'd.hsts' => [
				'label' => lng('domains.hsts'),
				'field' => 'hsts',
				'callback' => [Text::class, 'boolean'],
			],
			'd.http2' => [
				'label' => lng('admin.domain_http2.title'),
				'field' => 'http2',
				'callback' => [Text::class, 'boolean'],
			],
			'd.http3' => [
				'label' => lng('admin.domain_http3.title'),
				'field' => 'http3',
				'callback' => [Text::class, 'boolean'],
			],
			'd.letsencrypt' => [
				'label' => lng('panel.letsencrypt'),
				'field' => 'letsencrypt',
				'callback' => [Text::class, 'boolean'],
			],
			'd.deactivated' => [
				'label' => lng('admin.deactivated'),
				'field' => 'deactivated',
				'callback' => [Text::class, 'boolean'],
			],
		],
		'visible_columns' => Listing::getVisibleColumnsForListing('domain_list', [
			'd.domain_ace',
			'c.name',
			'c.loginname',
			'd.aliasdomain',
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
			],
			'duplicate' => [
				'icon' => 'fa-solid fa-clone',
				'title' => lng('admin.domain_duplicate'),
				'modal' => [Text::class, 'domainDuplicateModal'],
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
				'visible' => [Domain::class, 'adminCanEditDNS']
			],
			'domainssleditor' => [
				'callback' => [Domain::class, 'editSSLButtons'],
			],
			'letsencrypt' => [
				'icon' => 'fa-solid fa-shield',
				'title' => lng('panel.letsencrypt'),
				'visible' => [Domain::class, 'hasLetsEncryptActivated']
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
				'visible' => [Domain::class, 'adminCanDelete']
			]
		],
		'format_callback' => [
			[Style::class, 'resultDomainTerminatedOrDeactivated']
		]
	]
];
