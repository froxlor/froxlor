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

use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\MysqlServer;
use Froxlor\CurrentUser;
use Froxlor\Database\Database;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\UI\Collection;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

$id = (int)Request::any('id');

if (($page == 'customers' || $page == 'overview') && $userinfo['customers'] != '0') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_customers");

		try {
			$customer_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.customers.php';
			$collection = (new Collection(Customers::class, $userinfo, ['show_usages' => true]))
				->withPagination($customer_list_data['customer_list']['columns'], $customer_list_data['customer_list']['default_sorting']);
			if ($userinfo['change_serversettings']) {
				$collection->has('admin', Admins::class, 'adminid', 'adminid');
			}
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		$actions_links = false;
		if (CurrentUser::canAddResource('customers')) {
			$actions_links = [
				[
					'href' => $linker->getLink(['section' => 'customers', 'page' => $page, 'action' => 'add']),
					'label' => lng('admin.customer_add')
				]
			];
		}

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $customer_list_data, 'customer_list'),
			'actions_links' => $actions_links
		]);
	} elseif ($action == 'su' && $id != 0) {
		try {
			$json_result = Customers::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		$destination_user = $result['loginname'];

		if ($destination_user != '') {
			if ($result['deactivated'] == '1') {
				Response::standardError("usercurrentlydeactivated", $destination_user);
			}

			$result['switched_user'] = CurrentUser::getData();
			$result['adminsession'] = 0;
			$result['userid'] = $result['customerid'];
			session_regenerate_id(true);
			CurrentUser::setData($result);

			$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "switched user and is now '" . $destination_user . "'");

			$target = Request::get('target', 'index');
			$redirect = "customer_" . $target . ".php";
			if (!file_exists(Froxlor::getInstallDir() . "/" . $redirect)) {
				$redirect = "customer_index.php";
			}
			Response::redirectTo($redirect, null, true);
		} else {
			Response::redirectTo('index.php', [
				'action' => 'login'
			]);
		}
	} elseif ($action == 'unlock' && $id != 0) {
		try {
			$json_result = Customers::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (Request::post('send') == 'send') {
			try {
				$json_result = Customers::getLocal($userinfo, [
					'id' => $id
				])->unlock();
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			HTML::askYesNo('customer_reallyunlock', $filename, [
				'id' => $id,
				'page' => $page,
				'action' => $action
			], $result['loginname']);
		}
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = Customers::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (Request::post('send') == 'send') {
			try {
				$json_result = Customers::getLocal($userinfo, [
					'id' => $id,
					'delete_userfiles' => Request::post('delete_userfiles', 0)
				])->delete();
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			HTML::askYesNoWithCheckbox('admin_customer_reallydelete', 'admin_customer_alsoremovefiles', $filename, [
				'id' => $id,
				'page' => $page,
				'action' => $action
			], $result['loginname']);
		}
	} elseif ($action == 'add') {
		if (Request::post('send') == 'send') {
			try {
				Customers::getLocal($userinfo, Request::postAll())->add();
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
					$mysql_servers[] = [
						'label' => $dbdata['caption'],
						'value' => $dbserver
					];
				}
			} catch (Exception $e) {
				/* just none */
			}

			$phpconfigs = [];
			$configs = Database::query("
				SELECT c.*, fc.description as interpreter
				FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
				LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fc ON fc.id = c.fpmsettingid
			");
			while ($row = $configs->fetch(PDO::FETCH_ASSOC)) {
				if ((int)Settings::Get('phpfpm.enabled') == 1) {
					$phpconfigs[] = [
						'label' => $row['description'] . " [" . $row['interpreter'] . "]",
						'value' => $row['id']
					];
				} else {
					$phpconfigs[] = [
						'label' => $row['description'],
						'value' => $row['id']
					];
				}
			}

			// hosting plans
			$hosting_plans = [];
			$plans = Database::query("
				SELECT *
				FROM `" . TABLE_PANEL_PLANS . "`
				ORDER BY name ASC
			");
			$hosting_plans = [
				0 => "---"
			];
			while ($row = $plans->fetch(PDO::FETCH_ASSOC)) {
				$hosting_plans[$row['id']] = $row['name'];
			}

			$customer_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/customer/formfield.customer_add.php';

			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'customers']),
				'formdata' => $customer_add_data['customer_add']
			]);
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = Customers::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['loginname'] != '') {
			if (Request::post('send') == 'send') {
				try {
					Customers::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$dec_places = Settings::Get('panel.decimal_places');
				$result['traffic'] = round($result['traffic'] / (1024 * 1024), $dec_places);
				$result['diskspace'] = round($result['diskspace'] / 1024, $dec_places);
				$result['email'] = $idna_convert->decode($result['email']);

				$result = PhpHelper::htmlentitiesArray($result);

				$mysql_servers = [];
				try {
					$result_json = MysqlServer::getLocal($userinfo)->listing();
					$result_decoded = json_decode($result_json, true)['data']['list'];
					foreach ($result_decoded as $dbserver => $dbdata) {
						$mysql_servers[] = [
							'label' => $dbdata['caption'],
							'value' => $dbserver
						];
					}
				} catch (Exception $e) {
					/* just none */
				}

				$phpconfigs = [];
				$configs = Database::query("
					SELECT c.*, fc.description as interpreter
					FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
					LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fc ON fc.id = c.fpmsettingid
				");
				while ($row = $configs->fetch(PDO::FETCH_ASSOC)) {
					if ((int)Settings::Get('phpfpm.enabled') == 1) {
						$phpconfigs[] = [
							'label' => $row['description'] . " [" . $row['interpreter'] . "]",
							'value' => $row['id']
						];
					} else {
						$phpconfigs[] = [
							'label' => $row['description'],
							'value' => $row['id']
						];
					}
				}

				// hosting plans
				$plans = Database::query("
					SELECT *
					FROM `" . TABLE_PANEL_PLANS . "`
					ORDER BY name ASC
				");
				$hosting_plans = [
					0 => "---"
				];
				while ($row = $plans->fetch(PDO::FETCH_ASSOC)) {
					$hosting_plans[$row['id']] = $row['name'];
				}

				$admin_select = [];
				if ($userinfo['customers_see_all'] == '1') {
					$available_admins_stmt = Database::prepare("
						SELECT * FROM `" . TABLE_PANEL_ADMINS . "`
						WHERE (`customers` = '-1' OR `customers` > `customers_used`)
						AND adminid <> :currentadmin
					");
					Database::pexecute($available_admins_stmt, ['currentadmin' => $result['adminid']]);
					$admin_select = [
						0 => "---"
					];
					while ($available_admin = $available_admins_stmt->fetch()) {
						$admin_select[$available_admin['adminid']] = $available_admin['name'] . " (" . $available_admin['loginname'] . ")";
					}
				}

				$customer_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/customer/formfield.customer_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'customers', 'id' => $id]),
					'formdata' => $customer_edit_data['customer_edit'],
					'editid' => $id
				]);
			}
		}
	}
}
