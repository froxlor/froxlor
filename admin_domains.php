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

const AREA = 'admin';
require __DIR__ . '/lib/init.php';

use Froxlor\Api\Commands\Customers as Customers;
use Froxlor\Api\Commands\Domains as Domains;
use Froxlor\Bulk\DomainBulkAction;
use Froxlor\Cron\TaskId;
use Froxlor\CurrentUser;
use Froxlor\Customer\Customer;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\UI\Collection;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\User;
use Froxlor\Validate\Validate;

$id = (int)Request::any('id');

if ($page == 'domains' || $page == 'overview') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_domains");

		try {
			$customerCollection = (new Collection(Customers::class, $userinfo));
			$domain_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.domains.php';
			$collection = (new Collection(Domains::class, $userinfo))
				->has('customer', Customers::class, 'customerid', 'customerid')
				->withPagination($domain_list_data['domain_list']['columns'], $domain_list_data['domain_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		$actions_links = false;
		if (CurrentUser::canAddResource('domains')) {
			$actions_links = [];
			$actions_links[] = [
				'href' => $linker->getLink(['section' => 'domains', 'page' => $page, 'action' => 'add']),
				'label' => lng('admin.domain_add')
			];
			$actions_links[] = [
				'href' => $linker->getLink(['section' => 'domains', 'page' => $page, 'action' => 'import']),
				'label' => lng('domains.domain_import'),
				'icon' => 'fa-solid fa-file-import',
				'class' => 'btn-outline-secondary'
			];
		}

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $domain_list_data, 'domain_list'),
			'actions_links' => $actions_links
		]);
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = Domains::getLocal($userinfo, [
				'id' => $id,
				'no_std_subdomain' => true
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		$alias_check_stmt = Database::prepare("
			SELECT COUNT(`id`) AS `count` FROM `" . TABLE_PANEL_DOMAINS . "`
			WHERE `aliasdomain`= :id");
		$alias_check = Database::pexecute_first($alias_check_stmt, [
			'id' => $id
		]);

		if ($result['domain'] != '') {
			if (Request::post('send') == 'send' && $alias_check['count'] == 0) {
				try {
					Domains::getLocal($userinfo, Request::postAll())->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}

				Response::redirectTo($filename, [
					'page' => $page
				]);
			} elseif ($alias_check['count'] > 0) {
				Response::standardError('domains_cantdeletedomainwithaliases');
			} else {
				HTML::askYesNoWithCheckbox('admin_domain_reallydelete', 'admin_customer_alsoremovemail', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $idna_convert->decode($result['domain']));
			}
		}
	} elseif ($action == 'add') {
		if (Request::post('send') == 'send') {
			try {
				Domains::getLocal($userinfo, Request::postAll())->add();
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			$customers = [
				0 => lng('panel.please_choose')
			];
			$result_customers_stmt = Database::prepare("
					SELECT `customerid`, `loginname`, `name`, `firstname`, `company`
					FROM `" . TABLE_PANEL_CUSTOMERS . "` " . ($userinfo['customers_see_all'] ? '' : " WHERE `adminid` = :adminid ") . " ORDER BY COALESCE(NULLIF(`name`,''), `company`) ASC");
			$params = [];
			if ($userinfo['customers_see_all'] == '0') {
				$params['adminid'] = $userinfo['adminid'];
			}
			Database::pexecute($result_customers_stmt, $params);

			while ($row_customer = $result_customers_stmt->fetch(PDO::FETCH_ASSOC)) {
				$customers[$row_customer['customerid']] = User::getCorrectFullUserDetails($row_customer) . ' (' . $row_customer['loginname'] . ')';
			}

			$admins = [];
			if ($userinfo['customers_see_all'] == '1') {
				$result_admins_stmt = Database::query("
						SELECT `adminid`, `loginname`, `name`
						FROM `" . TABLE_PANEL_ADMINS . "`
						WHERE `domains_used` < `domains` OR `domains` = '-1' ORDER BY `name` ASC");

				while ($row_admin = $result_admins_stmt->fetch(PDO::FETCH_ASSOC)) {
					$admins[$row_admin['adminid']] = User::getCorrectFullUserDetails($row_admin) . ' (' . $row_admin['loginname'] . ')';
				}
			}

			if ($userinfo['ip'] == "-1") {
				$result_ipsandports_stmt = Database::query("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='0' ORDER BY `ip`, `port` ASC
					");
				$result_ssl_ipsandports_stmt = Database::query("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='1' ORDER BY `ip`, `port` ASC
					");
			} else {
				$admin_ip_stmt = Database::prepare("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `id` = :ipid ORDER BY `ip`, `port` ASC
					");
				$admin_ip = Database::pexecute_first($admin_ip_stmt, [
					'ipid' => $userinfo['ip']
				]);

				$result_ipsandports_stmt = Database::prepare("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='0' AND `ip` = :ipid ORDER BY `ip`, `port` ASC
					");
				Database::pexecute($result_ipsandports_stmt, [
					'ipid' => $admin_ip['ip']
				]);

				$result_ssl_ipsandports_stmt = Database::prepare("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='1' AND `ip` = :ipid ORDER BY `ip`, `port` ASC
					");
				Database::pexecute($result_ssl_ipsandports_stmt, [
					'ipid' => $admin_ip['ip']
				]);
			}

			// Build array holding all IPs and Ports available to this admin
			$ipsandports = [];
			while ($row_ipandport = $result_ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
				if (filter_var($row_ipandport['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
					$row_ipandport['ip'] = '[' . $row_ipandport['ip'] . ']';
				}

				$ipsandports[] = [
					'label' => $row_ipandport['ip'] . ':' . $row_ipandport['port'],
					'value' => $row_ipandport['id']
				];
			}

			$ssl_ipsandports = [];
			while ($row_ssl_ipandport = $result_ssl_ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
				if (filter_var($row_ssl_ipandport['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
					$row_ssl_ipandport['ip'] = '[' . $row_ssl_ipandport['ip'] . ']';
				}

				$ssl_ipsandports[] = [
					'label' => $row_ssl_ipandport['ip'] . ':' . $row_ssl_ipandport['port'],
					'value' => $row_ssl_ipandport['id']
				];
			}

			$standardsubdomains = [];
			$result_standardsubdomains_stmt = Database::query("
					SELECT `id` FROM `" . TABLE_PANEL_DOMAINS . "` `d`, `" . TABLE_PANEL_CUSTOMERS . "` `c` WHERE `d`.`id` = `c`.`standardsubdomain`
				");

			while ($row_standardsubdomain = $result_standardsubdomains_stmt->fetch(PDO::FETCH_ASSOC)) {
				$standardsubdomains[$row_standardsubdomain['id']] = $row_standardsubdomain['id'];
			}

			if (count($standardsubdomains) > 0) {
				$standardsubdomains = " AND `d`.`id` NOT IN (" . join(',', $standardsubdomains) . ") ";
			} else {
				$standardsubdomains = '';
			}

			$domains = [
				0 => lng('domains.noaliasdomain')
			];
			$result_domains_stmt = Database::prepare("
					SELECT `d`.`id`, `d`.`domain`, `c`.`loginname` FROM `" . TABLE_PANEL_DOMAINS . "` `d`, `" . TABLE_PANEL_CUSTOMERS . "` `c`
					WHERE `d`.`aliasdomain` IS NULL AND `d`.`parentdomainid` = 0" . $standardsubdomains . ($userinfo['customers_see_all'] ? '' : " AND `d`.`adminid` = :adminid") . "
					AND `d`.`customerid`=`c`.`customerid` ORDER BY `loginname`, `domain` ASC
				");
			$params = [];
			if ($userinfo['customers_see_all'] == '0') {
				$params['adminid'] = $userinfo['adminid'];
			}
			Database::pexecute($result_domains_stmt, $params);

			while ($row_domain = $result_domains_stmt->fetch(PDO::FETCH_ASSOC)) {
				$domains[$row_domain['id']] = $idna_convert->decode($row_domain['domain']) . ' (' . $row_domain['loginname'] . ')';
			}

			$phpconfigs = [];
			$configs = Database::query("
					SELECT c.*, fc.description as interpreter
					FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
					LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fc ON fc.id = c.fpmsettingid
				");

			while ($row = $configs->fetch(PDO::FETCH_ASSOC)) {
				if ((int)Settings::Get('phpfpm.enabled') == 1) {
					$phpconfigs[$row['id']] = $row['description'] . " [" . $row['interpreter'] . "]";
				} else {
					$phpconfigs[$row['id']] = $row['description'];
				}
			}

			$openbasedir = [
				0 => lng('domain.docroot'),
				1 => lng('domain.homedir'),
				2 => lng('domain.docparent')
			];

			// create serveralias options
			$serveraliasoptions = [
				0 => lng('domains.serveraliasoption_wildcard'),
				1 => lng('domains.serveraliasoption_www'),
				2 => lng('domains.serveraliasoption_none')
			];

			$subcanemaildomain = [
				0 => lng('admin.subcanemaildomain.never'),
				1 => lng('admin.subcanemaildomain.choosableno'),
				2 => lng('admin.subcanemaildomain.choosableyes'),
				3 => lng('admin.subcanemaildomain.always')
			];

			$domain_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/domains/formfield.domains_add.php';

			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'domains']),
				'formdata' => $domain_add_data['domain_add']
			]);
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = Domains::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['domain'] != '') {
			$subdomains_stmt = Database::prepare("
				SELECT COUNT(`id`) AS count FROM `" . TABLE_PANEL_DOMAINS . "` WHERE
				`parentdomainid` = :resultid
			");
			$subdomains = Database::pexecute_first($subdomains_stmt, [
				'resultid' => $result['id']
			]);
			$subdomains = $subdomains['count'];

			$alias_check_stmt = Database::prepare("
				SELECT COUNT(`id`) AS count FROM `" . TABLE_PANEL_DOMAINS . "` WHERE
				`aliasdomain` = :resultid
			");
			$alias_check = Database::pexecute_first($alias_check_stmt, [
				'resultid' => $result['id']
			]);
			$alias_check = $alias_check['count'];

			$domain_emails_result_stmt = Database::prepare("
				SELECT `email`, `email_full`, `destination`, `popaccountid`
				FROM `" . TABLE_MAIL_VIRTUAL . "` WHERE `customerid` = :customerid AND `domainid` = :id
			");
			Database::pexecute($domain_emails_result_stmt, [
				'customerid' => $result['customerid'],
				'id' => $result['id']
			]);

			$emails = Database::num_rows();
			$email_forwarders = 0;
			$email_accounts = 0;

			while ($domain_emails_row = $domain_emails_result_stmt->fetch(PDO::FETCH_ASSOC)) {
				if ($domain_emails_row['destination'] != '') {
					$domain_emails_row['destination'] = explode(' ', FileDir::makeCorrectDestination($domain_emails_row['destination']));
					$email_forwarders += count($domain_emails_row['destination']);

					if (in_array($domain_emails_row['email_full'], $domain_emails_row['destination'])) {
						$email_forwarders -= 1;
						$email_accounts++;
					}
				}
			}

			$ipsresult_stmt = Database::prepare("
				SELECT `id_ipandports` FROM `" . TABLE_DOMAINTOIP . "` WHERE `id_domain` = :id
			");
			Database::pexecute($ipsresult_stmt, [
				'id' => $result['id']
			]);

			$usedips = [];
			while ($ipsresultrow = $ipsresult_stmt->fetch(PDO::FETCH_ASSOC)) {
				$usedips[] = $ipsresultrow['id_ipandports'];
			}

			if (Request::post('send') == 'send') {
				try {
					// remove ssl ip/ports if set is empty
					if (empty(Request::post('ssl_ipandport'))) {
						$_POST['remove_ssl_ipandport'] = true;
					}
					Domains::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				if (Settings::Get('panel.allow_domain_change_customer') == '1') {
					$customers = [];
					$result_customers_stmt = Database::prepare("
						SELECT `customerid`, `loginname`, `name`, `firstname`, `company` FROM `" . TABLE_PANEL_CUSTOMERS . "`
						WHERE ( (`subdomains_used` + :subdomains <= `subdomains` OR `subdomains` = '-1' )
						AND (`emails_used` + :emails <= `emails` OR `emails` = '-1' )
						AND (`email_forwarders_used` + :forwarders <= `email_forwarders` OR `email_forwarders` = '-1' )
						AND (`email_accounts_used` + :accounts <= `email_accounts` OR `email_accounts` = '-1' ) " . ($userinfo['customers_see_all'] ? '' : " AND `adminid` = :adminid ") . ")
						OR `customerid` = :customerid ORDER BY `name` ASC
					");
					$params = [
						'subdomains' => $subdomains,
						'emails' => $emails,
						'forwarders' => $email_forwarders,
						'accounts' => $email_accounts,
						'customerid' => $result['customerid']
					];
					if ($userinfo['customers_see_all'] == '0') {
						$params['adminid'] = $userinfo['adminid'];
					}
					Database::pexecute($result_customers_stmt, $params);

					while ($row_customer = $result_customers_stmt->fetch(PDO::FETCH_ASSOC)) {
						$customers[$row_customer['customerid']] = User::getCorrectFullUserDetails($row_customer) . ' (' . $row_customer['loginname'] . ')';
					}
				} else {
					$customer_stmt = Database::prepare("
						SELECT `customerid`, `loginname`, `name`, `firstname`, `company` FROM `" . TABLE_PANEL_CUSTOMERS . "`
						WHERE `customerid` = :customerid
					");
					$customer = Database::pexecute_first($customer_stmt, [
						'customerid' => $result['customerid']
					]);
					$result['customername'] = User::getCorrectFullUserDetails($customer);
				}

				if ($userinfo['customers_see_all'] == '1') {
					if (Settings::Get('panel.allow_domain_change_admin') == '1') {
						$admins = [];
						$result_admins_stmt = Database::prepare("
							SELECT `adminid`, `loginname`, `name` FROM `" . TABLE_PANEL_ADMINS . "`
							WHERE (`domains_used` < `domains` OR `domains` = '-1') OR `adminid` = :adminid ORDER BY `name` ASC
						");
						Database::pexecute($result_admins_stmt, [
							'adminid' => $result['adminid']
						]);

						while ($row_admin = $result_admins_stmt->fetch(PDO::FETCH_ASSOC)) {
							$admins[$row_admin['adminid']] = User::getCorrectFullUserDetails($row_admin) . ' (' . $row_admin['loginname'] . ')';
						}
					} else {
						$admin_stmt = Database::prepare("
							SELECT `adminid`, `loginname`, `name` FROM `" . TABLE_PANEL_ADMINS . "` WHERE `adminid` = :adminid
						");
						$admin = Database::pexecute_first($admin_stmt, [
							'adminid' => $result['adminid']
						]);
						$result['adminname'] = User::getCorrectFullUserDetails($admin) . ' (' . $admin['loginname'] . ')';
					}
				}

				$domains = [
					0 => lng('domains.noaliasdomain')
				];

				$result_domains_stmt = Database::prepare("
					SELECT `d`.`id`, `d`.`domain`  FROM `" . TABLE_PANEL_DOMAINS . "` `d`, `" . TABLE_PANEL_CUSTOMERS . "` `c`
					WHERE `d`.`aliasdomain` IS NULL AND `d`.`parentdomainid` = '0' AND `d`.`id` <> :id
					AND `c`.`standardsubdomain`<>`d`.`id` AND `d`.`customerid` = :customerid AND `c`.`customerid`=`d`.`customerid`
					ORDER BY `d`.`domain` ASC
				");
				Database::pexecute($result_domains_stmt, [
					'id' => $result['id'],
					'customerid' => $result['customerid']
				]);

				while ($row_domain = $result_domains_stmt->fetch(PDO::FETCH_ASSOC)) {
					$domains[$row_domain['id']] = $idna_convert->decode($row_domain['domain']);
				}

				if ($userinfo['ip'] == "-1") {
					$result_ipsandports_stmt = Database::query("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='0' ORDER BY `ip`, `port` ASC
					");
					$result_ssl_ipsandports_stmt = Database::query("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='1' ORDER BY `ip`, `port` ASC
					");
				} else {
					$admin_ip_stmt = Database::prepare("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `id` = :ipid ORDER BY `ip`, `port` ASC
					");
					$admin_ip = Database::pexecute_first($admin_ip_stmt, [
						'ipid' => $userinfo['ip']
					]);

					$result_ipsandports_stmt = Database::prepare("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='0' AND `ip` = :ipid ORDER BY `ip`, `port` ASC
					");
					Database::pexecute($result_ipsandports_stmt, [
						'ipid' => $admin_ip['ip']
					]);

					$result_ssl_ipsandports_stmt = Database::prepare("
						SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='1' AND `ip` = :ipid ORDER BY `ip`, `port` ASC
					");
					Database::pexecute($result_ssl_ipsandports_stmt, [
						'ipid' => $admin_ip['ip']
					]);
				}

				$ipsandports = [];
				while ($row_ipandport = $result_ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
					if (filter_var($row_ipandport['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
						$row_ipandport['ip'] = '[' . $row_ipandport['ip'] . ']';
					}
					$ipsandports[] = [
						'label' => $row_ipandport['ip'] . ':' . $row_ipandport['port'],
						'value' => $row_ipandport['id']
					];
				}

				$ssl_ipsandports = [];
				while ($row_ssl_ipandport = $result_ssl_ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
					if (filter_var($row_ssl_ipandport['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
						$row_ssl_ipandport['ip'] = '[' . $row_ssl_ipandport['ip'] . ']';
					}
					$ssl_ipsandports[] = [
						'label' => $row_ssl_ipandport['ip'] . ':' . $row_ssl_ipandport['port'],
						'value' => $row_ssl_ipandport['id']
					];
				}

				// check that letsencrypt is not activated for wildcard domain
				if ($result['iswildcarddomain'] == '1') {
					$letsencrypt = 0;
				}

				// Fudge the result for ssl_redirect to hide the Let's Encrypt steps
				$result['temporary_ssl_redirect'] = $result['ssl_redirect'];
				$result['ssl_redirect'] = ($result['ssl_redirect'] == 0 ? 0 : 1);

				$openbasedir = [
					0 => lng('domain.docroot'),
					1 => lng('domain.homedir'),
					2 => lng('domain.docparent')
				];

				$serveraliasoptions = [
					0 => lng('domains.serveraliasoption_wildcard'),
					1 => lng('domains.serveraliasoption_www'),
					2 => lng('domains.serveraliasoption_none')
				];

				$subcanemaildomain = [
					0 => lng('admin.subcanemaildomain.never'),
					1 => lng('admin.subcanemaildomain.choosableno'),
					2 => lng('admin.subcanemaildomain.choosableyes'),
					3 => lng('admin.subcanemaildomain.always')
				];

				$phpconfigs = [];
				$phpconfigs_result_stmt = Database::query("
					SELECT c.*, fc.description as interpreter
					FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
					LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fc ON fc.id = c.fpmsettingid
				");
				$c_allowed_configs = Customer::getCustomerDetail($result['customerid'], 'allowed_phpconfigs');
				if (!empty($c_allowed_configs)) {
					$c_allowed_configs = json_decode($c_allowed_configs, true);
				} else {
					$c_allowed_configs = [];
				}

				while ($phpconfigs_row = $phpconfigs_result_stmt->fetch(PDO::FETCH_ASSOC)) {
					$disabled = !empty($c_allowed_configs) && !in_array($phpconfigs_row['id'], $c_allowed_configs);
					if (!$disabled) {
						if ((int)Settings::Get('phpfpm.enabled') == 1) {
							$phpconfigs[$phpconfigs_row['id']] = $phpconfigs_row['description'] . " [" . $phpconfigs_row['interpreter'] . "]";
						} else {
							$phpconfigs[$phpconfigs_row['id']] = $phpconfigs_row['description'];
						}
					}
				}

				if (Settings::Get('panel.allow_domain_change_customer') != '1') {
					$result['customername'] .= ' (<a href="' . $linker->getLink([
							'section' => 'customers',
							'page' => 'customers',
							'action' => 'su',
							'id' => $customer['customerid']
						]) . '" rel="external">' . $customer['loginname'] . '</a>)';
				}

				$domain_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/domains/formfield.domains_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'domains', 'id' => $id]),
					'formdata' => $domain_edit_data['domain_edit'],
					'editid' => $id
				]);
			}
		}
	} elseif ($action == 'jqGetCustomerPHPConfigs') {
		$customerid = intval(Request::post('customerid'));
		$allowed_phpconfigs = Customer::getCustomerDetail($customerid, 'allowed_phpconfigs');
		echo !empty($allowed_phpconfigs) ? $allowed_phpconfigs : json_encode([]);
		exit();
	} elseif ($action == 'jqSpeciallogfileNote') {
		$domainid = intval(Request::post('id'));
		$newval = intval(Request::post('newval'));
		try {
			$json_result = Domains::getLocal($userinfo, [
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
	} elseif ($action == 'jqEmaildomainNote') {
		$domainid = intval(Request::post('id'));
		$newval = intval(Request::post('newval'));
		try {
			$json_result = Domains::getLocal($userinfo, [
				'id' => $domainid
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];
		if ((int)$newval == 0 && $newval != $result['isemaildomain']) {
			echo json_encode(['changed' => true, 'info' => lng('admin.emaildomainwarning')]);
			exit();
		}
		echo 0;
		exit();
	} elseif ($action == 'import') {
		if (Request::post('send') == 'send') {
			$separator = Validate::validate(Request::post('separator'), 'separator');
			$offset = (int)Validate::validate(Request::post('offset'), 'offset', "/[0-9]/i");

			$file_name = $_FILES['file']['tmp_name'];

			$result = [];

			try {
				$bulk = new DomainBulkAction($file_name, $userinfo);
				$result = $bulk->doImport($separator, $offset);
			} catch (Exception $e) {
				Response::standardError('domain_import_error', $e->getMessage());
			}

			if (!empty($bulk->getErrors())) {
				Response::dynamicError(implode("<br>", $bulk->getErrors()));
			}

			// update customer/admin counters
			User::updateCounters(false);
			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			Cronjob::inserttask(TaskId::REBUILD_DNS);

			$result_str = $result['imported'] . ' / ' . $result['all'] . (!empty($result['note']) ? ' (' . $result['note'] . ')' : '');
			Response::standardSuccess('domain_import_successfully', $result_str, [
				'filename' => $filename,
				'action' => '',
				'page' => 'domains'
			]);
		} else {
			$domain_import_data = include_once dirname(__FILE__) . '/lib/formfields/admin/domains/formfield.domains_import.php';

			UI::view('user/form-note.html.twig', [
				'formaction' => $linker->getLink(['section' => 'domains', 'page' => $page]),
				'formdata' => $domain_import_data['domain_import'],
				// alert-box
				'type' => 'info',
				'alert_msg' => lng('domains.import_description')
			]);
		}
	} elseif ($action == 'duplicate') {
		if (Request::post('send') == 'send') {
			try {
				Domains::getLocal($userinfo, Request::postAll())->duplicate();
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}
			Response::redirectTo($filename, [
				'page' => $page,
				'searchfield' => 'd.domain_ace',
				'searchtext' => Request::post('domain', "")
			]);
		} else {
			Response::redirectTo($filename, [
				'page' => 'overview'
			]);
		}
	}
} elseif ($page == 'domainssleditor') {
	require_once __DIR__ . '/ssl_editor.php';
} elseif ($page == 'domaindnseditor' && Settings::Get('system.dnsenabled') == '1') {
	require_once __DIR__ . '/dns_editor.php';
} elseif ($page == 'sslcertificates') {
	require_once __DIR__ . '/ssl_certificates.php';
} elseif ($page == 'logfiles') {
	require_once __DIR__ . '/logfiles_viewer.php';
}
