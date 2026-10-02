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

use Froxlor\Api\Commands\FpmDaemons;
use Froxlor\Api\Commands\PhpSettings;
use Froxlor\Database\Database;
use Froxlor\Froxlor;
use Froxlor\UI\Collection;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

$id = (int)Request::any('id');

if ($page == 'overview') {
	if ($action == '') {
		try {
			$phpconf_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.phpconfigs.php';
			$collection = (new Collection(PhpSettings::class, $userinfo, ['with_subdomains' => true]))
				->withPagination($phpconf_list_data['phpconf_list']['columns'], $phpconf_list_data['phpconf_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $phpconf_list_data, 'phpconf_list'),
			'actions_links' => (bool)$userinfo['change_serversettings'] ? [
				[
					'href' => $linker->getLink(['section' => 'phpsettings', 'page' => $page, 'action' => 'add']),
					'label' => lng('admin.phpsettings.addnew')
				]
			] : []
		]);
	}

	if ($action == 'add') {
		if ((int)$userinfo['change_serversettings'] == 1) {
			if (Request::post('send') == 'send') {
				try {
					PhpSettings::getLocal($userinfo, Request::postAll())->add();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				if (file_exists(Froxlor::getInstallDir() . '/templates/misc/php/default.ini.php')) {
					include Froxlor::getInstallDir() . '/templates/misc/php/default.ini.php';
					$result = [
						'phpsettings' => $phpini
					];
				} else {
					// use first php-config as fallback
					$result_stmt = Database::query("SELECT * FROM `" . TABLE_PANEL_PHPCONFIGS . "` WHERE `id` = 1");
					$result = $result_stmt->fetch(PDO::FETCH_ASSOC);
				}

				$fpmconfigs = [];
				$configs = Database::query("SELECT * FROM `" . TABLE_PANEL_FPMDAEMONS . "` ORDER BY `description` ASC");
				while ($row = $configs->fetch(PDO::FETCH_ASSOC)) {
					$fpmconfigs[$row['id']] = $row['description'];
				}

				$phpconfig_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/phpconfig/formfield.phpconfig_add.php';

				UI::view('user/form-replacers.html.twig', [
					'formaction' => $linker->getLink(['section' => 'phpsettings']),
					'formdata' => $phpconfig_add_data['phpconfig_add'],
					'replacers' => $phpconfig_add_data['phpconfig_replacers']
				]);
			}
		} else {
			Response::standardError('nopermissionsorinvalidid');
		}
	}

	if ($action == 'delete') {
		try {
			$json_result = PhpSettings::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['id'] != 0 && $result['id'] == $id && (int)$userinfo['change_serversettings'] == 1 && $id != 1) // cannot delete the default php.config
		{
			if (Request::post('send') == 'send') {
				try {
					PhpSettings::getLocal($userinfo, [
						'id' => $id
					])->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNo('phpsetting_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $result['description']);
			}
		} else {
			Response::standardError('nopermissionsorinvalidid');
		}
	}

	if ($action == 'edit') {
		try {
			$json_result = PhpSettings::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['id'] != 0 && $result['id'] == $id && (int)$userinfo['change_serversettings'] == 1) {
			if (Request::post('send') == 'send') {
				try {
					PhpSettings::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$fpmconfigs = [];
				$configs = Database::query("SELECT * FROM `" . TABLE_PANEL_FPMDAEMONS . "` ORDER BY `description` ASC");
				while ($row = $configs->fetch(PDO::FETCH_ASSOC)) {
					$fpmconfigs[$row['id']] = $row['description'];
				}

				$phpconfig_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/phpconfig/formfield.phpconfig_edit.php';

				UI::view('user/form-replacers.html.twig', [
					'formaction' => $linker->getLink(['section' => 'phpsettings', 'id' => $id]),
					'formdata' => $phpconfig_edit_data['phpconfig_edit'],
					'replacers' => $phpconfig_edit_data['phpconfig_replacers'],
					'editid' => $id
				]);
			}
		} else {
			Response::standardError('nopermissionsorinvalidid');
		}
	}
} elseif ($page == 'fpmdaemons') {
	if ($action == '') {
		try {
			$fpmconf_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.fpmconfigs.php';
			$collection = (new Collection(FpmDaemons::class, $userinfo))
				->withPagination($fpmconf_list_data['fpmconf_list']['columns'], $fpmconf_list_data['fpmconf_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}

		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $fpmconf_list_data, 'fpmconf_list'),
			'actions_links' => (bool)$userinfo['change_serversettings'] ? [
				[
					'href' => $linker->getLink(['section' => 'phpsettings', 'page' => $page, 'action' => 'add']),
					'label' => lng('admin.fpmsettings.addnew')
				]
			] : []
		]);
	}

	if ($action == 'add') {
		if ((int)$userinfo['change_serversettings'] == 1) {
			if (Request::post('send') == 'send') {
				try {
					FpmDaemons::getLocal($userinfo, Request::postAll())->add();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$fpmconfig_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/phpconfig/formfield.fpmconfig_add.php';

				UI::view('user/form-replacers.html.twig', [
					'formaction' => $linker->getLink(['section' => 'phpsettings', 'page' => 'fpmdaemons']),
					'formdata' => $fpmconfig_add_data['fpmconfig_add'],
					'replacers' => $fpmconfig_add_data['fpmconfig_replacers']
				]);
			}
		} else {
			Response::standardError('nopermissionsorinvalidid');
		}
	}

	if ($action == 'delete') {
		try {
			$json_result = FpmDaemons::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($id == 1) {
			Response::standardError('cannotdeletedefaultphpconfig');
		}

		if ($result['id'] != 0 && $result['id'] == $id && (int)$userinfo['change_serversettings'] == 1 && $id != 1) // cannot delete the default php.config
		{
			if (Request::post('send') == 'send') {
				try {
					FpmDaemons::getLocal($userinfo, Request::postAll())->delete();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				HTML::askYesNo('fpmsetting_reallydelete', $filename, [
					'id' => $id,
					'page' => $page,
					'action' => $action
				], $result['description']);
			}
		} else {
			Response::standardError('nopermissionsorinvalidid');
		}
	}

	if ($action == 'edit') {
		try {
			$json_result = FpmDaemons::getLocal($userinfo, [
				'id' => $id
			])->get();
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		$result = json_decode($json_result, true)['data'];

		if ($result['id'] != 0 && $result['id'] == $id && (int)$userinfo['change_serversettings'] == 1) {
			if (Request::post('send') == 'send') {
				try {
					FpmDaemons::getLocal($userinfo, Request::postAll())->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::redirectTo($filename, [
					'page' => $page
				]);
			} else {
				$fpmconfig_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/phpconfig/formfield.fpmconfig_edit.php';

				UI::view('user/form-replacers.html.twig', [
					'formaction' => $linker->getLink(['section' => 'phpsettings', 'page' => 'fpmdaemons', 'id' => $id]),
					'formdata' => $fpmconfig_edit_data['fpmconfig_edit'],
					'replacers' => $fpmconfig_edit_data['fpmconfig_replacers'],
					'editid' => $id
				]);
			}
		} else {
			Response::standardError('nopermissionsorinvalidid');
		}
	}
}
