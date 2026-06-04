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

namespace Froxlor\UI\Callbacks;

use Froxlor\CurrentUser;
use Froxlor\Database\Database;
use Froxlor\Froxlor;
use Froxlor\PhpHelper;
use Froxlor\System\Markdown;
use Froxlor\UI\Panel\UI;
use Froxlor\User;
use PDO;

class Text
{
	public static function boolean(array $attributes): array
	{
		return [
			'macro' => 'boolean',
			'data' => (bool)$attributes['data']
		];
	}

	public static function yesno(array $attributes): array
	{
		return [
			'macro' => 'boolean',
			'data' => $attributes['data'] == 'Y'
		];
	}

	public static function type2fa(array $attributes): array
	{
		return [
			'macro' => 'type2fa',
			'data' => (int)$attributes['data']
		];
	}

	public static function customerfullname(array $attributes): string
	{
		return User::getCorrectFullUserDetails($attributes['fields'], true);
	}

	public static function size(array $attributes): string
	{
		return PhpHelper::sizeReadable($attributes['data'], null, 'bi');
	}

	public static function timestamp(array $attributes): string
	{
		return (int)$attributes['data'] > 0 ? date('d.m.Y H:i', (int)$attributes['data']) : lng('panel.never');
	}

	public static function timestampUntil(array $attributes): string
	{
		return (int)$attributes['data'] > 0 ? date('d.m.Y H:i', (int)$attributes['data']) : lng('panel.unlimited');
	}

	public static function crondesc(array $attributes): string
	{
		return lng('crondesc.' . $attributes['data']);
	}

	public static function shorten(array $attributes): string
	{
		return substr($attributes['data'], 0, 20) . '...';
	}

	public static function wordwrap(array $attributes): string
	{
		return wordwrap(htmlspecialchars($attributes['data']), 100, '<br>', true);
	}

	public static function customerNoteDetailModal(array $attributes): array
	{
		$note = $attributes['fields']['custom_notes'] ?? '';
		$key = $attributes['fields']['customerid'] ?? $attributes['fields']['adminid'];
		return [
			'entry' => $key,
			'id' => 'cnModal' . $key,
			'title' => lng('usersettings.custom_notes.title') . ': ' . ($attributes['fields']['loginname'] ?? $attributes['fields']['adminname']),
			'body' => nl2br(Markdown::cleanCustomNotes($note))
		];
	}

	public static function apikeyDetailModal(array $attributes): array
	{
		$linker = UI::getLinker();
		$result = $attributes['fields'];
		$apikey_data = include Froxlor::getInstallDir() . '/lib/formfields/formfield.api_key.php';

		$body = UI::twig()->render(UI::validateThemeTemplate('/user/inline-form.html.twig'), [
			'formaction' => $linker->getLink(['section' => 'index', 'page' => 'apikeys']),
			'formdata' => $apikey_data['apikey'],
			'editid' => $attributes['fields']['id']
		]);
		return [
			'entry' => $attributes['fields']['id'],
			'id' => 'akModal' . $attributes['fields']['id'],
			'title' => 'API-key ' . ($attributes['fields']['loginname'] ?? $attributes['fields']['adminname']),
			'action' => 'apikeys',
			'body' => $body
		];
	}

	public static function domainDuplicateModal(array $attributes): array
	{
		$linker = UI::getLinker();
		$result = $attributes['fields'];

		$customers = [
			0 => lng('panel.please_choose')
		];
		$result_customers_stmt = Database::prepare("
			SELECT `customerid`, `loginname`, `name`, `firstname`, `company`
			FROM `" . TABLE_PANEL_CUSTOMERS . "` " . (CurrentUser::getField('customers_see_all') ? '' : " WHERE `adminid` = :adminid ") . "
			ORDER BY COALESCE(NULLIF(`name`,''), `company`) ASC
		");
		$params = [];
		if (CurrentUser::getField('customers_see_all') == '0') {
			$params['adminid'] = CurrentUser::getField('adminid');
		}
		Database::pexecute($result_customers_stmt, $params);

		while ($row_customer = $result_customers_stmt->fetch(PDO::FETCH_ASSOC)) {
			$customers[$row_customer['customerid']] = User::getCorrectFullUserDetails($row_customer) . ' (' . $row_customer['loginname'] . ')';
		}

		$domdup_data = include Froxlor::getInstallDir() . '/lib/formfields/admin/domains/formfield.domains_duplicate.php';

		$body = UI::twig()->render(UI::validateThemeTemplate('/user/inline-form.html.twig'), [
			'formaction' => $linker->getLink(['section' => 'domains', 'page' => 'domains', 'action' => 'duplicate']),
			'formdata' => $domdup_data['domain_duplicate'],
			'editid' => $attributes['fields']['id'],
			'nosubmit' => 0
		]);
		return [
			'entry' => $attributes['fields']['id'],
			'id' => 'ddModal' . $attributes['fields']['id'],
			'title' => lng('admin.domain_duplicate_named', [$attributes['fields']['domain']]),
			'action' => 'duplicate',
			'body' => $body
		];
	}
}
