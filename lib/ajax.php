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

namespace Froxlor;

use Exception;
use Froxlor\Ajax\Ajax;

require_once dirname(__DIR__) . '/vendor/autoload.php';

// Load the user settings
if (!file_exists('./userdata.inc.php')) {
	die();
}
require_once dirname(__DIR__) . '/lib/userdata.inc.php';
require_once dirname(__DIR__) . '/lib/functions.php';
require_once dirname(__DIR__) . '/lib/tables.inc.php';

// Return response
try {
	echo (new Ajax)->handle();
} catch (Exception $e) {
	header("Content-Type: application/json");
	echo \Froxlor\Api\Response::jsonErrorResponse($e->getMessage(), 500);
}
