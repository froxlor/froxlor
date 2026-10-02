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

namespace Froxlor\Cron\System;

use Froxlor\Cron\FroxlorCron;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use PDO;

class MailboxsizeCron extends FroxlorCron
{

	public static function run()
	{
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, 'calculating mailspace usage');

		$maildirs_stmt = Database::query("
			SELECT `id`, CONCAT(`homedir`, `maildir`) AS `maildirpath` FROM `" . TABLE_MAIL_USERS . "` ORDER BY `id`
		");

		$upd_stmt = Database::prepare("
			UPDATE `" . TABLE_MAIL_USERS . "` SET `mboxsize` = :size WHERE `id` = :id
		");

		while ($maildir = $maildirs_stmt->fetch(PDO::FETCH_ASSOC)) {
			$_maildir = FileDir::makeCorrectDir($maildir['maildirpath']);

			if (file_exists($_maildir) && is_dir($_maildir)) {

				// compute actual maildirsize with `du`
				// mail-address allows many special characters, see http://en.wikipedia.org/wiki/Email_address#Local_part
				$return = false;
				$back = FileDir::safe_exec('du -sk ' . escapeshellarg($_maildir), $return, [
					'|',
					'&',
					'`',
					'$',
					'~',
					'?'
				]);
				foreach ($back as $backrow) {
					$emailusage = explode(' ', $backrow);
				}
				$emailusage = floatval($emailusage['0']);

				// as freebsd does not have the -b flag for 'du' which gives
				// the size in bytes, we use "-sk" for all and calculate from KiB
				$emailusage *= 1024;

				unset($back);

				Database::pexecute($upd_stmt, [
					'size' => $emailusage,
					'id' => $maildir['id']
				]);
			} else {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, 'maildir ' . $_maildir . ' does not exist');
			}
		}
	}
}
