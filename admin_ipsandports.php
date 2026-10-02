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

use Froxlor\Api\Commands\IpsAndPorts;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\UI\Collection;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

$id = (int)Request::any('id');

if (($page == 'ipsandports' || $page == 'overview') && $userinfo['change_serversettings'] == '1') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_ipsandports");

		try {
			$ipsandports_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.ipsandports.php';
			$collection = (new Collection(IpsAndPorts::class, $userinfo))
				->withPagination($ipsandports_list_data['ipsandports_list']['columns'], $ipsandports_list_data['ipsandports_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $ipsandports_list_data, 'ipsandports_list'),
			'actions_links' => [
				[
					'href' => $linker->getLink(['section' => 'ipsandports', 'page' => $page, 'action' => 'add']),
					'label' => lng('admin.ipsandports.add')
				]
			]
		]);
	} elseif ($action == 'delete' && $id != 0) {
		try {
			$json_result = IpsAndPorts::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if (isset($result['id']) && $result['id'] == $id) {
			if (Request::post('send') == 'send') {
				try {
					IpsAndPorts::getLocal($userinfo, [
						'id' => $id
					])->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}

				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNo('admin_ip_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $result['ip'] . ':' . $result['port']);
			}
		}
	} elseif ($action == 'add') {
		if (Request::post('send') == 'send') {
			try {
				IpsAndPorts::getLocal($userinfo, Request::postAll())->add();
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			$ipsandports_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/ipsandports/formfield.ipsandports_add.php';

			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'ipsandports']),
				'formdata' => $ipsandports_add_data['ipsandports_add']
			]);
		}
	} elseif ($action == 'edit' && $id != 0) {
		try {
			$json_result = IpsAndPorts::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['ip'] != '') {
			if (Request::post('send') == 'send') {
				try {
					IpsAndPorts::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$result = PhpHelper::htmlentitiesArray($result);

				$ipsandports_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/ipsandports/formfield.ipsandports_edit.php';

				UI::view('user/form.html.twig', [
					'formaction' => $linker->getLink(['section' => 'ipsandports', 'id' => $id]),
					'formdata' => $ipsandports_edit_data['ipsandports_edit'],
					'editid' => $id
				]);
			}
		}
	} elseif ($action == 'jqCheckIP') {
		$ip = Request::post('ip', '');
		if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
			echo json_encode('<div id="ipnote" class="invalid-feedback">'.lng('error.invalidip', [$ip]).'</div>');
		} elseif (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_NO_PRIV_RANGE)) {
			// returns notice if private network detected, so we can display it
			echo json_encode(lng('admin.ipsandports.ipnote'));
		} else {
			echo 0;
		}
		exit();
	}
}
