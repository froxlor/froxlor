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

namespace Froxlor\System;

use Froxlor\Settings;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;

class Mailer extends PHPMailer
{

	/**
	 * class constructor
	 *
	 * @param bool $exceptions whether to throw exceptions or not
	 *
	 * @throws Exception
	 */
	public function __construct(bool $exceptions = false)
	{
		parent::__construct($exceptions);
		$this->CharSet = "UTF-8";

		if (Settings::Get('system.mail_use_smtp')) {
			$this->isSMTP();
			$this->Host = Settings::Get('system.mail_smtp_host');
			$this->SMTPAuth = Settings::Get('system.mail_smtp_auth') == '1';
			$this->Username = Settings::Get('system.mail_smtp_user');
			$this->Password = Settings::Get('system.mail_smtp_passwd');
			if (Settings::Get('system.mail_smtp_usetls')) {
				$this->SMTPSecure = 'tls';
			} else {
				$this->SMTPAutoTLS = false;
			}
			$this->Port = Settings::Get('system.mail_smtp_port');
		}

		/**
		 * use froxlor's email-validation
		 */
		self::$validator = [
			'\Froxlor\\Validate\\Validate',
			'validateEmail'
		];

		if (self::ValidateAddress(Settings::Get('panel.adminmail')) !== false) {
			// set return-to address and custom sender-name, see #76
			$this->setFrom(Settings::Get('panel.adminmail'), Settings::Get('panel.adminmail_defname'));
			if (Settings::Get('panel.adminmail_return') != '') {
				$this->addReplyTo(Settings::Get('panel.adminmail_return'), Settings::Get('panel.adminmail_defname'));
			}
		}
	}
}
