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

use Froxlor\Api\Commands\Mysqls;
use Froxlor\Api\Commands\MysqlServer;
use Froxlor\CurrentUser;
use Froxlor\Database\Database;
use Froxlor\Database\DbManager;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\System\Crypt;
use Froxlor\UI\Collection;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

// redirect if this customer page is hidden via settings or no resources given
if (Settings::IsInList('panel.customer_hide_options', 'mysql') || $userinfo['mysqls'] == 0) {
	Response::redirectTo('customer_index.php');
}

// get sql-root access data
Database::needRoot(true);
Database::needSqlData();
$sql_root = Database::getSqlData();
Database::needRoot(false);

$id = (int)Request::any('id');

if ($page == 'overview' || $page == 'mysqls') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, "viewed customer_mysql::mysqls");

		$multiple_mysqlservers = count(json_decode($userinfo['allowed_mysqlserver'] ?? '[]', true)) > 1;

		try {
			$mysql_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/customer/tablelisting.mysqls.php';
			$collection = (new Collection(Mysqls::class, $userinfo))
				->withPagination($mysql_list_data['mysql_list']['columns'], $mysql_list_data['mysql_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		$actions_links = [];
		if (CurrentUser::canAddResource('mysqls')) {
			$actions_links[] = [
				'href' => $linker->getLink(['section' => 'mysql', 'page' => 'mysqls', 'action' => 'add']),
				'label' => lng('mysql.database_create')
			];
		}

		$view = 'user/table.html.twig';
		if ($collection->count() > 0) {
			$view = 'user/table-note.html.twig';

			$actions_links[] = [
				'href' => $linker->getLink(['section' => 'mysql', 'page' => 'mysqls', 'action' => 'global_user']),
				'label' => lng('mysql.edit_global_user'),
				'icon' => 'fa-solid fa-user-tie',
				'class' => 'btn-outline-secondary'
			];
		}

		$actions_links[] = [
			'href' => \Froxlor\Froxlor::getDocsUrl() . 'user-guide/databases/',
			'target' => '_blank',
			'icon' => 'fa-solid fa-circle-info',
			'class' => 'btn-outline-secondary'
		];

		UI::view($view, [
			'listing' => Listing::format($collection, $mysql_list_data, 'mysql_list'),
			'actions_links' => $actions_links,
			'entity_info' => lng('mysql.description'),
			// alert-box
			'type' => 'info',
			'alert_msg' => lng('mysql.globaluserinfo', [$userinfo['loginname']]),
		]);
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = Mysqls::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['databasename']) && $result['databasename'] != '') {
			Database::needRoot(true, $result['dbserver'], false);
			Database::needSqlData();
			$sql_root = Database::getSqlData();
			Database::needRoot(false);

			if (!isset($sql_root[$result['dbserver']]) || !is_array($sql_root[$result['dbserver']])) {
				$result['dbserver'] = 0;
			}

			if (Request::post('send') == 'send') {
				try {
					Mysqls::getLocal($userinfo, Request::postAll())->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$dbnamedesc = $result['databasename'];
				if (isset($result['description']) && $result['description'] != '') {
					$dbnamedesc .= ' (' . $result['description'] . ')';
				}
				HTML::askYesNo('mysql_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $dbnamedesc);
			}
		}
	} elseif ($action == 'add') {
		if ($userinfo['mysqls_used'] < $userinfo['mysqls'] || $userinfo['mysqls'] == '-1') {
			if (Request::post('send') == 'send') {
				try {
					Mysqls::getLocal($userinfo, Request::postAll())->add();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$mysql_servers = [];
				try {
					$result_json = MysqlServer::getLocal($userinfo)->listing();
					$result_decoded = json_decode($result_json, true)['data']['list'];
					foreach ($result_decoded as $dbserver => $dbdata) {
						$mysql_servers[$dbserver] = $dbdata['caption'];
					}
				} catch (Exception $e) {
					/* just none */
				}

				$mysql_add_data = include_once dirname(__FILE__) . '/lib/formfields/customer/mysql/formfield.mysql_add.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'mysql']),
					'formdata' => $mysql_add_data['mysql_add']
				]);
			}
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = Mysqls::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['databasename']) && $result['databasename'] != '') {
			if (Request::post('send') == 'send') {
				try {
					$json_result = Mysqls::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$mysql_servers = [];
				try {
					$result_json = MysqlServer::getLocal($userinfo)->listing();
					$result_decoded = json_decode($result_json, true)['data']['list'];
					foreach ($result_decoded as $dbserver => $dbdata) {
						$mysql_servers[$dbserver] = $dbdata['caption'] . ' (' . $dbdata['host'] . (isset($dbdata['port']) && !empty($dbdata['port']) ? ':' . $dbdata['port'] : '') . ')';
					}
				} catch (Exception $e) {
					/* just none */
				}

				$mysql_edit_data = include_once dirname(__FILE__) . '/lib/formfields/customer/mysql/formfield.mysql_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'mysql', 'id' => $id]),
					'formdata' => $mysql_edit_data['mysql_edit'],
					'editid' => $id
				]);
			}
		}
	} elseif ($action == 'global_user') {

		$allowed_mysqlservers = json_decode($userinfo['allowed_mysqlserver'] ?? '[]', true);
		if ($userinfo['mysqls'] == 0 || empty($allowed_mysqlservers)) {
			Response::dynamicError('No permission');
		}

		if (Request::post('send') == 'send') {

			$new_password = Crypt::validatePassword(Request::post('mysql_password'));
			foreach ($allowed_mysqlservers as $dbserver) {
				// require privileged access for target db-server
				Database::needRoot(true, $dbserver, true);
				// get DbManager
				$dbm = new DbManager($log);
				// give permission to the user on every access-host we have
				foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
					if ($dbm->getManager()->userExistsOnHost($userinfo['loginname'], $mysql_access_host)) {
						// update password
						$dbm->getManager()->grantPrivilegesTo($userinfo['loginname'], $new_password, $mysql_access_host, false, true, true);
					} else {
						// create missing user
						$dbm->getManager()->grantPrivilegesTo($userinfo['loginname'], $new_password, $mysql_access_host, false, false, true);
					}
				}
				$dbm->getManager()->flushPrivileges();
			}

			Response::redirectTo($filename, [
				'page' => 'overview'
			]);
		} else {
			$mysql_global_user_data = include_once dirname(__FILE__) . '/lib/formfields/customer/mysql/formfield.mysql_global_user.php';

			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'mysql', 'page' => 'mysqls', 'action' => 'global_user']),
				'formdata' => $mysql_global_user_data['mysql_global_user'],
				'editid' => $id
			]);
		}
	}
}
