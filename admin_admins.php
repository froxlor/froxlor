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
use Froxlor\CurrentUser;
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

if (($page == 'admins' || $page == 'overview') && $userinfo['change_serversettings'] == '1') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_admins");

		try {
			$admin_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.admins.php';
			$collection = (new Collection(Admins::class, $userinfo))
				->withPagination($admin_list_data['admin_list']['columns'], $admin_list_data['admin_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $admin_list_data, 'admin_list'),
			'actions_links' => [
				[
					'href' => $linker->getLink(['section' => 'admins', 'page' => $page, 'action' => 'add']),
					'label' => lng('admin.admin_add')
				]
			]
		]);
	} elseif ($action == 'su') {
		try {
			$json_result = Admins::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];
		$destination_admin = $result['loginname'];

		if ($destination_admin != '' && $result['adminid'] != $userinfo['userid']) {
			$result['switched_user'] = CurrentUser::getData();
			$result['adminsession'] = 1;
			$result['userid'] = $result['adminid'];
			session_regenerate_id(true);
			CurrentUser::setData($result);

			$log->logAction(
                FroxlorLogger::ADM_ACTION,
                LOG_INFO,
                "switched adminuser and is now '" . $destination_admin . "'"
            );
			Response::redirectTo('admin_index.php');
		} else {
			Response::redirectTo('index.php', [
				'action' => 'login'
			]);
		}
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = Admins::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['loginname'] != '') {
			if ($result['adminid'] == $userinfo['userid']) {
				Response::standardError('youcantdeleteyourself');
			}

			if (Request::post('send') == 'send') {
				Admins::getLocal($userinfo, [
					'id' => $id
				])->delete();
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNo('admin_admin_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $result['loginname']);
			}
		}
	} elseif ($action == 'add') {
		if (Request::post('send') == 'send') {
			try {
				Admins::getLocal($userinfo, Request::postAll())->add();
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			$ipaddress = [];
			$ipaddress[-1] = lng('admin.allips');
			$ipsandports_stmt = Database::query("
				SELECT `id`, `ip` FROM `" . TABLE_PANEL_IPSANDPORTS . "` GROUP BY `ip` ORDER BY `ip` ASC
			");
			while ($row = $ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
				$ipaddress[$row['id']] = $row['ip'];
			}

			$admin_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/admin/formfield.admin_add.php';

			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'admins']),
				'formdata' => $admin_add_data['admin_add']
			]);
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = Admins::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['loginname'] != '') {
			if (Request::post('send') == 'send') {
				try {
					Admins::getLocal($userinfo, Request::postAll())->update();
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

				$ipaddress = [];
				$ipaddress[-1] = lng('admin.allips');
				$ipsandports_stmt = Database::query("
					SELECT `id`, `ip` FROM `" . TABLE_PANEL_IPSANDPORTS . "` GROUP BY `ip` ORDER BY `ip` ASC
				");
				while ($row = $ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
					$ipaddress[$row['id']] = $row['ip'];
				}

				$result = PhpHelper::htmlentitiesArray($result);

				$admin_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/admin/formfield.admin_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'admins', 'id' => $id]),
					'formdata' => $admin_edit_data['admin_edit'],
					'editid' => $id
				]);
			}
		}
	}
}
