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

use Froxlor\UI\Panel\UI;

class Impersonate
{
	public static function apiAdminCustomerLink(array $attributes)
	{
		// my own key
		$isMyKey = false;
		if ($attributes['fields']['adminid'] == UI::getCurrentUser()['adminid']
			&& ((AREA == 'admin' && $attributes['fields']['customerid'] == 0)
				|| (AREA == 'customer' && $attributes['fields']['customerid'] == UI::getCurrentUser()['customerid'])
			)
		) {
			// this is mine
			$isMyKey = true;
		}

		$adminCustomerLink = "";
		if (AREA == 'admin') {
			if ($isMyKey) {
				$adminCustomerLink = $attributes['fields']['adminname'];
			} else {
				if (empty($attributes['fields']['customerid'])) {
					$adminCustomerLink = self::admin($attributes);
				} else {
					$attributes['data'] = $attributes['fields']['loginname'];
					$adminCustomerLink = self::customer($attributes);
				}
			}
		} else {
			// customer do not need links
			$adminCustomerLink = $attributes['fields']['loginname'];
		}

		return $adminCustomerLink;
	}

	public static function admin(array $attributes)
	{
		if (UI::getCurrentUser()['adminid'] != $attributes['fields']['adminid']) {
			$linker = UI::getLinker();
			return [
				'macro' => 'link',
				'data' => [
					'text' => $attributes['data'],
					'href' => $linker->getLink([
						'section' => 'admins',
						'page' => 'admins',
						'action' => 'su',
						'id' => $attributes['fields']['adminid'],
					]),
				]
			];
		}
		return $attributes['data'];
	}

	public static function customer(array $attributes): array
	{
		$linker = UI::getLinker();
		return [
			'macro' => 'link',
			'data' => [
				'text' => $attributes['data'],
				'href' => $linker->getLink([
					'section' => 'customers',
					'page' => 'customers',
					'action' => 'su',
					'sort' => $attributes['fields']['loginname'],
					'id' => $attributes['fields']['customerid'],
				]),
			]
		];
	}
}
