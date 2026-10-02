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

const AREA = 'customer';
require __DIR__ . '/lib/init.php';

use Froxlor\Api\Commands\SubDomains;
use Froxlor\CurrentUser;
use Froxlor\Database\Database;
use Froxlor\Domain\Domain;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\UI\Collection;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;

// redirect if this customer page is hidden via settings
if (Settings::IsInList('panel.customer_hide_options', 'domains')) {
	Response::redirectTo('customer_index.php');
}

$id = (int)Request::any('id');

if ($page == 'overview' || $page == 'domains') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::USR_ACTION, LOG_INFO, "viewed customer_domains::domains");

		$parentdomain_id = (int)Request::any('pid', '0');

		try {
			$domain_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/customer/tablelisting.domains.php';
			$collection = (new Collection(SubDomains::class, $userinfo))
				->withPagination($domain_list_data['domain_list']['columns'], $domain_list_data['domain_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		$actions_links = [];
		if (CurrentUser::canAddResource('subdomains')) {
			$actions_links[] = [
				'href' => $linker->getLink(['section' => 'domains', 'page' => 'domains', 'action' => 'add']),
				'label' => lng('domains.subdomain_add')
			];
		}

		$actions_links[] = [
			'href' => \Froxlor\Froxlor::getDocsUrl() . 'user-guide/domains/',
			'target' => '_blank',
			'icon' => 'fa-solid fa-circle-info',
			'class' => 'btn-outline-secondary'
		];

		$table_tpl = 'table.html.twig';
		if ($collection->count() == 0) {
			$table_tpl = 'table-note.html.twig';
		}
		UI::view('user/' . $table_tpl, [
			'listing' => Listing::format($collection, $domain_list_data, 'domain_list'),
			'actions_links' => $actions_links,
			'entity_info' => lng('domains.description'),
			// alert-box
			'type' => 'warning',
			'alert_msg' => lng('domains.nodomainsassignedbyadmin')
		]);
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = SubDomains::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		$alias_stmt = Database::prepare("SELECT COUNT(`id`) AS `count` FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `aliasdomain` = :aliasdomain");
		$alias_check = Database::pexecute_first($alias_stmt, [
			"aliasdomain" => $id
		]);

		if (isset($result['parentdomainid']) && $result['parentdomainid'] != '0' && $alias_check['count'] == 0) {
			if (Request::post('send') == 'send') {
				try {
					SubDomains::getLocal($userinfo, Request::postAll())->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNo('domains_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $idna_convert->decode($result['domain']));
			}
		} else {
			Response::standardError('domains_cantdeletemaindomain');
		}
	} elseif ($action == 'add') {
		if ($userinfo['subdomains_used'] < $userinfo['subdomains'] || $userinfo['subdomains'] == '-1') {
			if (Request::post('send') == 'send') {
				try {
					SubDomains::getLocal($userinfo, Request::postAll())->add();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$stmt = Database::prepare("SELECT `id`, `domain`, `documentroot`, `ssl_redirect`,`isemaildomain`,`letsencrypt` FROM `" . TABLE_PANEL_DOMAINS . "`
					WHERE `customerid` = :customerid
					AND `parentdomainid` = '0'
					AND `email_only` = '0'
					AND `deactivated` = '0'
					ORDER BY `domain` ASC");
				Database::pexecute($stmt, [
					"customerid" => $userinfo['customerid']
				]);
				$domains = [];
				while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
					$domains[$row['domain']] = $idna_convert->decode($row['domain']);
				}

				// check of there are any domains to be used
				if (count($domains) <= 0) {
					// no, possible direct URL access, redirect to overview
					Response::redirectTo($filename, [
						'page' => $page
					]);
				}

				$aliasdomains[0] = lng('domains.noaliasdomain');
				$domains_stmt = Database::prepare("SELECT `d`.`id`, `d`.`domain` FROM `" . TABLE_PANEL_DOMAINS . "` `d`, `" . TABLE_PANEL_CUSTOMERS . "` `c`
					WHERE `d`.`aliasdomain` IS NULL
					AND `d`.`id` <> `c`.`standardsubdomain`
					AND `d`.`parentdomainid` = '0'
					AND `d`.`customerid`=`c`.`customerid`
					AND `d`.`email_only`='0'
					AND `d`.`customerid`= :customerid
					ORDER BY `d`.`domain` ASC");
				Database::pexecute($domains_stmt, [
					"customerid" => $userinfo['customerid']
				]);

				while ($row_domain = $domains_stmt->fetch(PDO::FETCH_ASSOC)) {
					$aliasdomains[$row_domain['id']] = $idna_convert->decode($row_domain['domain']);
				}

				$redirectcode = [];
				if (Settings::Get('customredirect.enabled') == '1') {
					$codes = Domain::getRedirectCodesArray();
					foreach ($codes as $rc) {
						$redirectcode[$rc['id']] = $rc['code'] . ' (' . lng('redirect_desc.' . $rc['desc']) . ')';
					}
				}

				// check if we at least have one ssl-ip/port, #1179
				$ssl_ipsandports = false;
				$ssl_ip_stmt = Database::prepare("
					SELECT COUNT(*) as countSSL
					FROM `" . TABLE_PANEL_IPSANDPORTS . "` pip
					LEFT JOIN `" . TABLE_DOMAINTOIP . "` dti ON dti.id_ipandports = pip.id
					WHERE pip.`ssl`='1'
				");
				Database::pexecute($ssl_ip_stmt);
				$resultX = $ssl_ip_stmt->fetch(PDO::FETCH_ASSOC);
				if (isset($resultX['countSSL']) && (int)$resultX['countSSL'] > 0) {
					$ssl_ipsandports = true;
				}

				$openbasedir = [
					0 => lng('domain.docroot'),
					1 => lng('domain.homedir'),
					2 => lng('domain.docparent')
				];
				$pathSelect = FileDir::makePathfield($userinfo['documentroot'], $userinfo['guid'], $userinfo['guid']);

				$phpconfigs = [];
				if (isset($userinfo['allowed_phpconfigs']) && !empty($userinfo['allowed_phpconfigs'])) {
					$allowed_cfg = json_decode($userinfo['allowed_phpconfigs'], JSON_OBJECT_AS_ARRAY);
					$phpconfigs_result_stmt = Database::query("
						SELECT c.*, fc.description as interpreter
						FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
						LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fc ON fc.id = c.fpmsettingid
						WHERE c.id IN (" . implode(", ", $allowed_cfg) . ")
					");
					while ($phpconfigs_row = $phpconfigs_result_stmt->fetch(PDO::FETCH_ASSOC)) {
						if ((int)Settings::Get('phpfpm.enabled') == 1) {
							$phpconfigs[$phpconfigs_row['id']] = $phpconfigs_row['description'] . " [" . $phpconfigs_row['interpreter'] . "]";
						} else {
							$phpconfigs[$phpconfigs_row['id']] = $phpconfigs_row['description'];
						}
					}
				}

				$subdomain_add_data = include_once dirname(__FILE__) . '/lib/formfields/customer/domains/formfield.domains_add.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'domains']),
					'formdata' => $subdomain_add_data['domain_add']
				]);
			}
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = SubDomains::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['customerid']) && $result['customerid'] == $userinfo['customerid']) {

			if ((int)$result['caneditdomain'] == 0) {
				Response::standardError('domaincannotbeedited', $result['domain']);
			}

			if (Request::post('send') == 'send') {
				try {
					SubDomains::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$result['domain'] = $idna_convert->decode($result['domain']);

				$domains[0] = lng('domains.noaliasdomain');
				// also check ip/port combination to be the same, #176
				$domains_stmt = Database::prepare("SELECT `d`.`id`, `d`.`domain` FROM `" . TABLE_PANEL_DOMAINS . "` `d` , `" . TABLE_PANEL_CUSTOMERS . "` `c` , `" . TABLE_DOMAINTOIP . "` `dip`
					WHERE `d`.`aliasdomain` IS NULL
					AND `d`.`id` <> :id
					AND `c`.`standardsubdomain` <> `d`.`id`
					AND `d`.`parentdomainid` = '0'
					AND `d`.`customerid` = :customerid
					AND `c`.`customerid` = `d`.`customerid`
					AND `d`.`id` = `dip`.`id_domain`
					AND `dip`.`id_ipandports`
					IN (SELECT `id_ipandports` FROM `" . TABLE_DOMAINTOIP . "`
						WHERE `id_domain` = :id)
					GROUP BY `d`.`id`, `d`.`domain`
					ORDER BY `d`.`domain` ASC");
				Database::pexecute($domains_stmt, [
					"id" => $result['id'],
					"customerid" => $userinfo['customerid']
				]);

				while ($row_domain = $domains_stmt->fetch(PDO::FETCH_ASSOC)) {
					$domains[$row_domain['id']] = $idna_convert->decode($row_domain['domain']);
				}

				if (preg_match('/^https?\:\/\//', $result['documentroot']) && Validate::validateUrl($result['documentroot'])) {
					if (Settings::Get('panel.pathedit') == 'Dropdown') {
						$urlvalue = $result['documentroot'];
						$pathSelect = FileDir::makePathfield($userinfo['documentroot'], $userinfo['guid'], $userinfo['guid']);
					} else {
						$urlvalue = '';
						$pathSelect = FileDir::makePathfield($userinfo['documentroot'], $userinfo['guid'], $userinfo['guid'], $result['documentroot'], true);
					}
				} else {
					$urlvalue = '';
					$pathSelect = FileDir::makePathfield($userinfo['documentroot'], $userinfo['guid'], $userinfo['guid'], $result['documentroot']);
				}

				$redirectcode = [];
				if (Settings::Get('customredirect.enabled') == '1') {
					$def_code = Domain::getDomainRedirectId($id);
					$codes = Domain::getRedirectCodesArray();
					foreach ($codes as $rc) {
						$redirectcode[$rc['id']] = $rc['code'] . ' (' . lng('redirect_desc.' . $rc['desc']) . ')';
					}
				}

				// check if we at least have one ssl-ip/port, #1179
				$ssl_ipsandports = false;
				$ssl_ip_stmt = Database::prepare("
					SELECT COUNT(*) as countSSL
					FROM `" . TABLE_PANEL_IPSANDPORTS . "` pip
					LEFT JOIN `" . TABLE_DOMAINTOIP . "` dti ON dti.id_ipandports = pip.id
					WHERE `dti`.`id_domain` = :id_domain AND pip.`ssl`='1'
				");
				Database::pexecute($ssl_ip_stmt, [
					"id_domain" => $result['id']
				]);
				$resultX = $ssl_ip_stmt->fetch(PDO::FETCH_ASSOC);
				if (isset($resultX['countSSL']) && (int)$resultX['countSSL'] > 0) {
					$ssl_ipsandports = true;
				}

				// Fudge the result for ssl_redirect to hide the Let's Encrypt steps
				$result['temporary_ssl_redirect'] = $result['ssl_redirect'];
				$result['ssl_redirect'] = ($result['ssl_redirect'] == 0 ? 0 : 1);

				$openbasedir = [
					0 => lng('domain.docroot'),
					1 => lng('domain.homedir'),
					2 => lng('domain.docparent')
				];

				// create serveralias options
				$serveraliasoptions = [];
				$serveraliasoptions_selected = '2';
				if ($result['iswildcarddomain'] == '1') {
					$serveraliasoptions_selected = '0';
				} elseif ($result['wwwserveralias'] == '1') {
					$serveraliasoptions_selected = '1';
				}
				$serveraliasoptions[0] = lng('domains.serveraliasoption_wildcard');
				$serveraliasoptions[1] = lng('domains.serveraliasoption_www');
				$serveraliasoptions[2] = lng('domains.serveraliasoption_none');

				$ips_stmt = Database::prepare("SELECT `p`.`ip` AS `ip` FROM `" . TABLE_PANEL_IPSANDPORTS . "` `p`
					LEFT JOIN `" . TABLE_DOMAINTOIP . "` `dip`
					ON ( `dip`.`id_ipandports` = `p`.`id` )
					WHERE `dip`.`id_domain` = :id_domain
					GROUP BY `p`.`ip`");
				Database::pexecute($ips_stmt, [
					"id_domain" => $result['id']
				]);
				$domainips = [];
				while ($rowip = $ips_stmt->fetch(PDO::FETCH_ASSOC)) {
					$domainips[] = ['item' => $rowip['ip']];
				}

				$phpconfigs = [];
				if (isset($userinfo['allowed_phpconfigs']) && !empty($userinfo['allowed_phpconfigs'])) {
					$allowed_cfg = json_decode($userinfo['allowed_phpconfigs'], JSON_OBJECT_AS_ARRAY);
					$phpconfigs_result_stmt = Database::query("
						SELECT c.*, fc.description as interpreter
						FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
						LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fc ON fc.id = c.fpmsettingid
						WHERE c.id IN (" . implode(", ", $allowed_cfg) . ")
					");
					while ($phpconfigs_row = $phpconfigs_result_stmt->fetch(PDO::FETCH_ASSOC)) {
						if ((int)Settings::Get('phpfpm.enabled') == 1) {
							$phpconfigs[$phpconfigs_row['id']] = $phpconfigs_row['description'] . " [" . $phpconfigs_row['interpreter'] . "]";
						} else {
							$phpconfigs[$phpconfigs_row['id']] = $phpconfigs_row['description'];
						}
					}
				}

				$alias_stmt = Database::prepare("SELECT COUNT(`id`) AS count FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `aliasdomain`= :aliasdomain");
				$alias_check = Database::pexecute_first($alias_stmt, [
					"aliasdomain" => $result['id']
				]);
				$alias_check = $alias_check['count'];

				$subdomain_edit_data = include_once dirname(__FILE__) . '/lib/formfields/customer/domains/formfield.domains_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'domains', 'id' => $id]),
					'formdata' => $subdomain_edit_data['domain_edit'],
					'editid' => $id
				]);
			}
		} else {
			Response::standardError('domains_canteditdomain');
		}
	} elseif ($action == 'jqSpeciallogfileNote') {
		$domainid = intval(Request::post('id'));
		$newval = intval(Request::post('newval'));
		try {
			$json_result = SubDomains::getLocal($userinfo, [
				'id' => $domainid
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];
		if ($newval != $result['speciallogfile']) {
			echo json_encode(['changed' => true, 'info' => lng('admin.speciallogwarning')]);
			exit();
		}
		echo 0;
		exit();
	}
} elseif ($page == 'domainssleditor') {
	require_once __DIR__ . '/ssl_editor.php';
} elseif ($page == 'domaindnseditor' && $userinfo['dnsenabled'] == '1' && Settings::Get('system.dnsenabled') == '1') {
	require_once __DIR__ . '/dns_editor.php';
} elseif ($page == 'sslcertificates') {
	require_once __DIR__ . '/ssl_certificates.php';
} elseif ($page == 'logfiles') {
	require_once __DIR__ . '/logfiles_viewer.php';
}
