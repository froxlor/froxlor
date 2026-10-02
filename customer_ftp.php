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

use Froxlor\Api\Commands\Ftps;
use Froxlor\Api\Commands\SshKeys;
use Froxlor\CurrentUser;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\UI\Collection;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

// redirect if this customer page is hidden via settings
if (Settings::IsInList('panel.customer_hide_options', 'ftp')) {
	Response::redirectTo('customer_index.php');
}

$id = (int)Request::any('id', 0);

if ($page == 'overview' || $page == 'accounts') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, "viewed customer_ftp::accounts");
		try {
			$ftp_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/customer/tablelisting.ftps.php';
			$collection = (new Collection(Ftps::class, $userinfo))
				->withPagination($ftp_list_data['ftp_list']['columns'], $ftp_list_data['ftp_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		$actions_links = [];
		if (CurrentUser::canAddResource('ftps')) {
			$actions_links[] = [
				'href' => $linker->getLink(['section' => 'ftp', 'page' => 'accounts', 'action' => 'add']),
				'label' => lng('ftp.account_add')
			];
		}
		$actions_links[] = [
			'href' => Froxlor::getDocsUrl() . 'user-guide/ftp-accounts/',
			'target' => '_blank',
			'icon' => 'fa-solid fa-circle-info',
			'class' => 'btn-outline-secondary'
		];

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $ftp_list_data, 'ftp_list'),
			'actions_links' => $actions_links,
			'entity_info' => lng('ftp.description')
		]);
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = Ftps::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['username']) && $result['username'] != $userinfo['loginname']) {
			if (Request::post('send') == 'send') {
				try {
					Ftps::getLocal($userinfo, Request::postAll())->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNoWithCheckbox('ftp_reallydelete', 'admin_customer_alsoremoveftphomedir', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $result['username']);
			}
		} else {
			Response::standardError('ftp_cantdeletemainaccount');
		}
	} elseif ($action == 'add') {
		if ($userinfo['ftps_used'] < $userinfo['ftps'] || $userinfo['ftps'] == '-1') {
			if (Request::post('send') == 'send') {
				try {
					Ftps::getLocal($userinfo, Request::postAll())->add();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$pathSelect = FileDir::makePathfield($userinfo['documentroot'], $userinfo['guid'], $userinfo['guid'], '/');

				if (Settings::Get('customer.ftpatdomain') == '1') {
					$domainlist = [];
					$result_domains_stmt = Database::prepare("SELECT `domain` FROM `" . TABLE_PANEL_DOMAINS . "`
						WHERE `customerid`= :customerid ORDER BY `domain` ASC");
					Database::pexecute($result_domains_stmt, [
						"customerid" => $userinfo['customerid']
					]);

					while ($row_domain = $result_domains_stmt->fetch(PDO::FETCH_ASSOC)) {
						$domainlist[$row_domain['domain']] = $idna_convert->decode($row_domain['domain']);
					}
				}

				$user_shell_allowed = intval($userinfo['shell_allowed']) == 1;
				if (Settings::Get('system.allow_customer_shell') == '1') {
					$shells['/bin/false'] = "/bin/false";
					$shells_avail = Settings::Get('system.available_shells');
					if (!empty($shells_avail)) {
						$shells_avail_arr = explode(",", $shells_avail);
						$shells_avail_arr = array_map("trim", $shells_avail_arr);
						foreach ($shells_avail_arr as $shell) {
							$shells[$shell] = $shell;
						}
					}
				}

				$ftp_add_data = include_once dirname(__FILE__) . '/lib/formfields/customer/ftp/formfield.ftp_add.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'ftp']),
					'formdata' => $ftp_add_data['ftp_add']
				]);
			}
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = Ftps::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['username']) && $result['username'] != '') {
			if (Request::post('send') == 'send') {
				try {
					Ftps::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				if (strpos($result['homedir'], $userinfo['documentroot']) === 0) {
					$homedir = str_replace($userinfo['documentroot'], "/", $result['homedir']);
				} else {
					$homedir = $result['homedir'];
				}
				$homedir = FileDir::makeCorrectDir($homedir);

				$pathSelect = FileDir::makePathfield($userinfo['documentroot'], $userinfo['guid'], $userinfo['guid'], $homedir);

				$user_shell_allowed = intval($userinfo['shell_allowed']) == 1;
				if (Settings::Get('system.allow_customer_shell') == '1') {
					$shells['/bin/false'] = "/bin/false";
					$shells_avail = Settings::Get('system.available_shells');
					if (!empty($shells_avail)) {
						$shells_avail_arr = explode(",", $shells_avail);
						$shells_avail_arr = array_map("trim", $shells_avail_arr);
						foreach ($shells_avail_arr as $shell) {
							$shells[$shell] = $shell;
						}
					}
				}

				$ftp_edit_data = include_once dirname(__FILE__) . '/lib/formfields/customer/ftp/formfield.ftp_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'ftp', 'id' => $id]),
					'formdata' => $ftp_edit_data['ftp_edit'],
					'editid' => $id
				]);
			}
		}
	}
} elseif ($page == 'sshkeys') {

	// redirect if this customer has no permission for API usage
	if ($userinfo['adminsession'] == 0 && (intval(Settings::Get('system.allow_customer_shell')) == 0 || $userinfo['shell_allowed'] == 0)) {
		Response::redirectTo('customer_index.php');
	}

	if ($action == '') {
		$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, "viewed customer_ftp::sshkeys");
		try {
			$sshkeys_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/customer/tablelisting.sshkeys.php';
			$collection = (new Collection(SshKeys::class, $userinfo))
				->withPagination($sshkeys_list_data['sshkeys_list']['columns'], $sshkeys_list_data['sshkeys_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		$actions_links = [];
		if (/* User-has-ftp-users-with-active-shell */
		true) {
			$actions_links[] = [
				'href' => $linker->getLink(['section' => 'ftp', 'page' => 'sshkeys', 'action' => 'add']),
				'label' => lng('ftp.sshkey_add')
			];
		}
		$actions_links[] = [
			'href' => Froxlor::getDocsUrl() . 'user-guide/ssh-keys/',
			'target' => '_blank',
			'icon' => 'fa-solid fa-circle-info',
			'class' => 'btn-outline-secondary'
		];

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $sshkeys_list_data, 'sshkeys_list'),
			'actions_links' => $actions_links,
			'entity_info' => lng('sshkeys.description')
		]);
	} elseif ($action == 'add') {

		if (Request::post('send') == 'send') {
			try {
				SshKeys::getLocal($userinfo, Request::postAll())->add();
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {

			$userList = [];
			$result_ftpusers_stmt = Database::prepare("
				SELECT `id`, `username`, `shell`
				FROM `" . TABLE_FTP_USERS . "`
				WHERE `customerid` = :customerid
				ORDER BY `username` ASC
			");
			Database::pexecute($result_ftpusers_stmt, [
				"customerid" => $userinfo['customerid']
			]);

			while ($row_ftpusers = $result_ftpusers_stmt->fetch(PDO::FETCH_ASSOC)) {
				$userList[$row_ftpusers['id']] = $row_ftpusers['username'] . ' (Shell: ' . $row_ftpusers['shell'] . ')';
			}

			$sshkey_add_data = include_once dirname(__FILE__) . '/lib/formfields/customer/ftp/formfield.ftp_ssh_add.php';

			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'ftp', 'page' => 'sshkeys']),
				'formdata' => $sshkey_add_data['sshkey_add']
			]);
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = SshKeys::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['ssh_pubkey']) && $result['ssh_pubkey'] != '') {
			if (Request::post('send') == 'send') {
				try {
					SshKeys::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {

				$sshkey_edit_data = include_once dirname(__FILE__) . '/lib/formfields/customer/ftp/formfield.ftp_ssh_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'ftp', 'page' => 'sshkeys', 'id' => $id]),
					'formdata' => $sshkey_edit_data['sshkey_edit'],
					'editid' => $id
				]);
			}
		}
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = SshKeys::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['ssh_pubkey']) && $result['ssh_pubkey'] != '') {
			if (Request::post('send') == 'send') {
				try {
					SshKeys::getLocal($userinfo, Request::postAll())->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNo('sshkey_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $result['fingerprint']);
			}
		}
	}
}
