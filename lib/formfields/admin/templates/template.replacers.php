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
return [
	'replacers' => [
		[
			'var' => 'SALUTATION',
			'description' => lng('admin.templates.SALUTATION')
		],
		[
			'var' => 'FIRSTNAME',
			'description' => lng('admin.templates.FIRSTNAME')
		],
		[
			'var' => 'NAME',
			'description' => lng('admin.templates.NAME')
		],
		[
			'var' => 'COMPANY',
			'description' => lng('admin.templates.COMPANY')
		],
		[
			'var' => 'CUSTOMER_NO',
			'description' => lng('admin.templates.CUSTOMER_NO')
		],
		[
			'var' => 'USERNAME',
			'description' => lng('admin.templates.USERNAME')
		],
		[
			'var' => 'PASSWORD',
			'description' => lng('admin.templates.PASSWORD'),
			'visible' => $template == 'createcustomer'
		],
		[
			'var' => 'EMAIL',
			'description' => lng('admin.templates.EMAIL'),
			'visible' => $template == 'pop_success'
		],
		[
			'var' => 'PASSWORD',
			'description' => lng('admin.templates.EMAIL_PASSWORD'),
			'visible' => $template == 'pop_success'
		],
		[
			'var' => 'LINK',
			'description' => lng('admin.templates.LINK'),
			'visible' => $template == 'password_reset'
		],
		[
			'var' => 'TRAFFIC',
			'description' => lng('admin.templates.TRAFFIC'),
			'visible' => $template == 'trafficmaxpercent'
		],
		[
			'var' => 'TRAFFICUSED',
			'description' => lng('admin.templates.TRAFFICUSED'),
			'visible' => $template == 'trafficmaxpercent'
		],
		[
			'var' => 'DISKAVAILABLE',
			'description' => lng('admin.templates.DISKAVAILABLE'),
			'visible' => $template == 'diskmaxpercent'
		],
		[
			'var' => 'DISKUSED',
			'description' => lng('admin.templates.DISKUSED'),
			'visible' => $template == 'diskmaxpercent'
		],
		[
			'var' => 'MAX_PERCENT',
			'description' => lng('admin.templates.MAX_PERCENT'),
			'visible' => $template == 'trafficmaxpercent' || $template == 'diskmaxpercent'
		],
		[
			'var' => 'USAGE_PERCENT',
			'description' => lng('admin.templates.USAGE_PERCENT'),
			'visible' => $template == 'trafficmaxpercent' || $template == 'diskmaxpercent'
		],
		[
			'var' => 'DB_NAME',
			'description' => lng('admin.templates.DB_NAME'),
			'visible' => $template == 'new_database_by_customer'
		],
		[
			'var' => 'DB_PASS',
			'description' => lng('admin.templates.DB_PASS'),
			'visible' => $template == 'new_database_by_customer'
		],
		[
			'var' => 'DB_DESC',
			'description' => lng('admin.templates.DB_DESC'),
			'visible' => $template == 'new_database_by_customer'
		],
		[
			'var' => 'DB_SRV',
			'description' => lng('admin.templates.DB_SRV'),
			'visible' => $template == 'new_database_by_customer'
		],
		[
			'var' => 'PMA_URI',
			'description' => lng('admin.templates.PMA_URI'),
			'visible' => $template == 'new_database_by_customer'
		],
		[
			'var' => 'USR_NAME',
			'description' => lng('admin.templates.USR_NAME'),
			'visible' => $template == 'new_ftpaccount_by_customer'
		],
		[
			'var' => 'USR_PASS',
			'description' => lng('admin.templates.USR_PASS'),
			'visible' => $template == 'new_ftpaccount_by_customer'
		],
		[
			'var' => 'USR_PATH',
			'description' => lng('admin.templates.USR_PATH'),
			'visible' => $template == 'new_ftpaccount_by_customer'
		]
	]
];
