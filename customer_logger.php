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

use Froxlor\Api\Commands\SysLog;
use Froxlor\Settings;
use Froxlor\UI\Collection;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Response;

// redirect if this customer page is hidden via settings
if (Settings::IsInList('panel.customer_hide_options', 'extras.logger')) {
	Response::redirectTo('customer_index.php');
}

if ($page == 'log') {
	if ($action == '') {
		try {
			$syslog_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/tablelisting.syslog.php';
			$collection = (new Collection(SysLog::class, $userinfo))
				->withPagination($syslog_list_data['syslog_list']['columns'], $syslog_list_data['syslog_list']['default_sorting']);
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		UI::view('user/table.html.twig', [
			'listing' => Listing::format($collection, $syslog_list_data, 'syslog_list')
		]);
	}
}
