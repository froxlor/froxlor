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

use Froxlor\Api\Commands\HostingPlans;
use Froxlor\Api\Commands\MysqlServer;
use Froxlor\Database\Database;
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

if ($page == '' || $page == 'overview') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_plans");

		try {
			$plan_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.plans.php';
			$collection = (new Collection(HostingPlans::class, $userinfo))
				->withPagination($plan_list_data['plan_list']['columns'], $plan_list_data['plan_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $plan_list_data, 'plan_list'),
			'actions_links' => [
				[
					'href' => $linker->getLink(['section' => 'plans', 'page' => $page, 'action' => 'add']),
					'label' => lng('admin.plans.add')
				]
			]
		]);
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = HostingPlans::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['id'] != 0 && $result['id'] == $id && (int)$userinfo['adminid'] == $result['adminid']) {
			if (Request::post('send') == 'send') {
				try {
					HostingPlans::getLocal($userinfo, [
						'id' => $id
					])->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}

				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNo('plan_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $result['name']);
			}
		} else {
			Response::standardError('nopermissionsorinvalidid');
		}
	} elseif ($action == 'add') {
		if (Request::post('send') == 'send') {
			try {
				HostingPlans::getLocal($userinfo, Request::postAll())->add();
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

			// dummy to avoid unknown variables
			$hosting_plans = null;

			$plans_add_data = include_once __DIR__ . '/lib/formfields/admin/plans/formfield.plans_add.php';
			$cust_add_data = include_once __DIR__ . '/lib/formfields/admin/customer/formfield.customer_add.php';
			// unset unneeded stuff
			unset($cust_add_data['customer_add']['sections']['section_a']);
			unset($cust_add_data['customer_add']['sections']['section_b']);
			unset($cust_add_data['customer_add']['sections']['section_cpre']);
			// merge
			$plans_add_data['plans_add']['sections'] = array_merge($plans_add_data['plans_add']['sections'], $cust_add_data['customer_add']['sections']);

			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'plans']),
				'formdata' => $plans_add_data['plans_add']
			]);
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = HostingPlans::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['name'] != '') {
			$result['value'] = json_decode($result['value'], true);
			$result = PhpHelper::htmlentitiesArray($result);

			foreach ($result['value'] as $index => $value) {
				$result[$index] = $value;
			}
			$result['allowed_phpconfigs'] = json_encode($result['allowed_phpconfigs']);

			if (Request::post('send') == 'send') {
				try {
					HostingPlans::getLocal($userinfo, Request::postAll())->update();
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

				$result['imap'] = $result['email_imap'];
				$result['pop3'] = $result['email_pop3'];

				// dummy to avoid unknown variables
				$result['loginname'] = null;
				$result['documentroot'] = null;
				$result['standardsubdomain'] = null;
				$result['deactivated'] = null;
				$result['def_language'] = null;
				$result['firstname'] = null;
				$result['gender'] = null;
				$result['company'] = null;
				$result['street'] = null;
				$result['zipcode'] = null;
				$result['city'] = null;
				$result['phone'] = null;
				$result['fax'] = null;
				$result['email'] = null;
				$result['customernumber'] = null;
				$result['custom_notes'] = null;
				$result['custom_notes_show'] = null;
				$result['api_allowed'] = null;
				$hosting_plans = null;
				$admin_select = [];

				$plans_edit_data = include_once __DIR__ . '/lib/formfields/admin/plans/formfield.plans_edit.php';
				$cust_edit_data = include_once __DIR__ . '/lib/formfields/admin/customer/formfield.customer_edit.php';
				// unset unneeded stuff
				unset($cust_edit_data['customer_edit']['sections']['section_a']);
				unset($cust_edit_data['customer_edit']['sections']['section_b']);
				unset($cust_edit_data['customer_edit']['sections']['section_cpre']);
				unset($cust_edit_data['customer_edit']['sections']['section_d']);
				// merge
				$plans_edit_data['plans_edit']['sections'] = array_merge($plans_edit_data['plans_edit']['sections'], $cust_edit_data['customer_edit']['sections']);

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'plans', 'id' => $id]),
					'formdata' => $plans_edit_data['plans_edit'],
					'editid' => $id
				]);
			}
		}
	} elseif ($action == 'jqGetPlanValues') {
		$planid = (int)Request::any('planid', 0);
		try {
			$json_result = HostingPlans::getLocal($userinfo, [
				'id' => $planid
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];
		echo $result['value'];
		exit();
	}
}
