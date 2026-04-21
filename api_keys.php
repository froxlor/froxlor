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

if (!defined('AREA')) {
	header("Location: index.php");
	exit();
}

use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

// redirect if this customer has no permission for API usage
if ($userinfo['adminsession'] == 0 && $userinfo['api_allowed'] == 0) {
	Response::redirectTo('customer_index.php');
}
// redirect if this admin has no permission for API usage
if ($userinfo['adminsession'] == 1 && $userinfo['api_allowed'] == 0) {
	Response::redirectTo('admin_index.php');
}

// This file is being included in admin_index and customer_index
// and therefore does not need to require lib/init.php

$del_stmt = Database::prepare("DELETE FROM `" . TABLE_API_KEYS . "` WHERE id = :id");
$id = (int)Request::any('id');

// do the delete and then just show a success-message and the apikeys list again
if ($action == 'delete' && $id > 0) {
	HTML::askYesNo('apikey_reallydelete', $filename, [
		'id' => $id,
		'page' => $page,
		'action' => 'deletesure'
	], '', [
		'section' => 'index',
		'page' => $page
	]);
} elseif (Request::post('send') == 'send' && $action == 'deletesure' && $id > 0) {
	$chk = (AREA == 'admin' && $userinfo['customers_see_all'] == '1') ? true : false;
	if (AREA == 'customer') {
		$chk_stmt = Database::prepare("
				SELECT c.customerid FROM `" . TABLE_PANEL_CUSTOMERS . "` c
				LEFT JOIN `" . TABLE_API_KEYS . "` ak ON ak.customerid = c.customerid
				WHERE ak.`id` = :id AND c.`customerid` = :cid
			");
		$chk = Database::pexecute_first($chk_stmt, [
			'id' => $id,
			'cid' => $userinfo['customerid']
		]);
	} elseif (AREA == 'admin' && $userinfo['customers_see_all'] == '0') {
		$chk_stmt = Database::prepare("
				SELECT a.adminid FROM `" . TABLE_PANEL_ADMINS . "` a
				LEFT JOIN `" . TABLE_API_KEYS . "` ak ON ak.adminid = a.adminid
				WHERE ak.`id` = :id AND a.`adminid` = :aid
			");
		$chk = Database::pexecute_first($chk_stmt, [
			'id' => $id,
			'aid' => $userinfo['adminid']
		]);
	}
	if ($chk !== false) {
		Database::pexecute($del_stmt, [
			'id' => $id
		]);
		Response::standardSuccess('apikeys.apikey_removed', $id, [
			'filename' => $filename,
			'page' => $page
		]);
	}
} elseif ($action == 'add') {
	if (Request::post('send') == 'send') {
		$user_passwd = Request::post('user_password');
		if (empty($user_passwd)) {
			Response::dynamicError(lng('panel.noauthentication'));
		}
		if ($userinfo['adminsession']) {
			$table = "`" . TABLE_PANEL_ADMINS . "`";
			$uid = 'adminid';
		} else {
			$table = "`" . TABLE_PANEL_CUSTOMERS . "`";
			$uid = 'customerid';
		}
		if (\Froxlor\System\Crypt::validatePasswordLogin($userinfo, $user_passwd, $table, $uid)) {
			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_API_KEYS . "` SET
				`apikey` = :key, `secret` = :secret, `adminid` = :aid, `customerid` = :cid, `valid_until` = '-1', `allowed_from` = ''
			");
			// customer generates for himself, admins will see a customer-select-box later
			if (AREA == 'admin') {
				$cid = 0;
			} elseif (AREA == 'customer') {
				$cid = $userinfo['customerid'];
			}
			$key = hash('sha256', openssl_random_pseudo_bytes(64 * 64));
			$secret = hash('sha512', openssl_random_pseudo_bytes(64 * 64 * 4));
			Database::pexecute($ins_stmt, [
				'key' => $key,
				'secret' => $secret,
				'aid' => $userinfo['adminid'],
				'cid' => $cid
			]);
			Response::standardSuccess('apikeys.apikey_added', '', [
				'filename' => $filename,
				'page' => $page
			]);
		} else {
			Response::dynamicError(lng('panel.authenticationfailed'));
		}
	}
	HTML::askUserPasswd('apikey_reallyadd', $filename, [
		'id' => $id,
		'page' => $page,
		'action' => $action
	], '', [
		'section' => 'index',
		'page' => $page
	]);
	exit;
}

$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, "viewed api::api_keys");

// select all my (accessible) api-keys
$keys_stmt_query = "SELECT ak.*, c.loginname, a.loginname as adminname
	FROM `" . TABLE_API_KEYS . "` ak
	LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON `c`.`customerid` = `ak`.`customerid`
	LEFT JOIN `" . TABLE_PANEL_ADMINS . "` a ON `a`.`adminid` = `ak`.`adminid`
	WHERE ";

$qry_params = [];
if (AREA == 'admin' && $userinfo['customers_see_all'] == '0') {
	// admin with only customer-specific permissions
	$keys_stmt_query .= "ak.adminid = :adminid ";
	$qry_params['adminid'] = $userinfo['adminid'];
	$fields = [
		'a.loginname' => lng('login.username')
	];
} elseif (AREA == 'customer') {
	// customer-area
	$keys_stmt_query .= "ak.customerid = :cid ";
	$qry_params['cid'] = $userinfo['customerid'];
	$fields = [
		'c.loginname' => lng('login.username')
	];
} else {
	// admin who can see all customers / reseller / admins
	$keys_stmt_query .= "1 ";
	$fields = [
		'a.loginname' => lng('login.username')
	];
}

//$keys_stmt_query .= $paging->getSqlWhere(true) . " " . $paging->getSqlOrderBy() . " " . $paging->getSqlLimit();

$keys_stmt = Database::prepare($keys_stmt_query);
Database::pexecute($keys_stmt, $qry_params);
$all_keys = $keys_stmt->fetchAll(PDO::FETCH_ASSOC);

$apikeys_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/tablelisting.apikeys.php';
$collection = [
	'data' => $all_keys,
	'pagination' => []
];

$tpl = 'user/table.html.twig';

UI::view($tpl, [
	'listing' => Listing::formatFromArray($collection, $apikeys_list_data['apikeys_list'], 'apikeys_list'),
	'actions_links' => (int)$userinfo['api_allowed'] == 1 ? [
		[
			'href' => $linker->getLink(['section' => 'index', 'page' => $page, 'action' => 'add']),
			'label' => lng('apikeys.key_add')
		]
	] : null,
]);
