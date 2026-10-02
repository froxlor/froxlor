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

use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\Database\Database;

// This file is being included in admin_domains and customer_domains
// and therefore does not need to require lib/init.php

$errid = Request::any('errorid');

if (!empty($errid)) {
	// read error file
	$err_dir = FileDir::makeCorrectDir(Froxlor::getInstallDir() . "/logs/");
	$err_file = FileDir::makeCorrectFile($err_dir . "/" . $errid . "_sql-error.log");

	if (file_exists($err_file)) {
		$error_content = file_get_contents($err_file);
		$error = explode("|", $error_content);

		$_error = [
			'code' => str_replace("\n", "", substr($error[1], 5)),
			'message' => str_replace("\n", "", substr($error[2], 4)),
			'file' => str_replace("\n", "", substr($error[3], 5 + strlen(Froxlor::getInstallDir()))),
			'line' => str_replace("\n", "", substr($error[4], 5)),
			'trace' => str_replace(Froxlor::getInstallDir(), "", substr($error[5], 6))
		];

		// build mail-content
		$mail_body = "Dear froxlor-team,\n\n";
		$mail_body .= "the following error has been reported by a user:\n\n";
		$mail_body .= "-------------------------------------------------------------\n";
		$mail_body .= $_error['code'] . ' ' . $_error['message'] . "\n\n";
		$mail_body .= "File: " . $_error['file'] . ':' . $_error['line'] . "\n\n";
		$mail_body .= "Trace:\n" . trim($_error['trace']) . "\n\n";
		$mail_body .= "-------------------------------------------------------------\n\n";
		$mail_body .= "User-Area: " . AREA . "\n";
		$mail_body .= "Froxlor-version: " . Froxlor::VERSION . "\n";
		$mail_body .= "DB-version: " . Froxlor::DBVERSION . "\n\n";
		try {
			$mail_body .= "Database: " . Database::getAttribute(PDO::ATTR_SERVER_VERSION);
		} catch (\Exception $e) {
			/* ignore */
		}
		$mail_body .= "End of report";
		$mail_html = nl2br($mail_body);

		// send actual report to dev-team
		if (Request::post('send') == 'send') {
			// send mail and say thanks
			$_mailerror = false;
			try {
				$mail->Subject = '[Froxlor] Error report by user';
				$mail->AltBody = $mail_body;
				$mail->MsgHTML($mail_html);
				$mail->AddAddress('error-reports@froxlor.org', 'Froxlor Developer Team');
				$mail->Send();
			} catch (\PHPMailer\PHPMailer\Exception $e) {
				$mailerr_msg = $e->errorMessage();
				$_mailerror = true;
			} catch (Exception $e) {
				$mailerr_msg = $e->getMessage();
				$_mailerror = true;
			}

			if ($_mailerror) {
				// error when reporting an error...LOLFUQ
				Response::standardError('send_report_error', $mailerr_msg);
			}

			// finally remove error from fs
			@unlink($err_file);
			Response::standardSuccess('sent_error_report', '', ['filename' => 'index.php']);
		}
		// show a nice summary of the error-report
		// before actually sending anything
		UI::view('user/error_report.html.twig', [
			'mail_html' => $mail_body,
			'errorid' => $errid
		]);
	} else {
		Response::redirectTo($filename);
	}
} else {
	Response::redirectTo($filename);
}
