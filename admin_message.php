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

use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\User;

$id = (int)Request::any('id');

$note_type = null;
$note_msg = null;

if ($page == 'message') {
	if ($action == '') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, 'viewed panel_message');

		if (Request::post('send') == 'send') {
			if (Request::post('recipient', -1) == 0 && $userinfo['customers_see_all'] == '1') {
				$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, 'sending messages to admins');
				$result = Database::query('SELECT `name`, `email`  FROM `' . TABLE_PANEL_ADMINS . "`");
			} elseif (Request::post('recipient', -1) == 1) {
				if ($userinfo['customers_see_all'] == '1') {
					$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, 'sending messages to ALL customers');
					$result = Database::query('SELECT `firstname`, `name`, `company`, `email`  FROM `' . TABLE_PANEL_CUSTOMERS . "`");
				} else {
					$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, 'sending messages to customers');
					$result = Database::prepare('
						SELECT `firstname`, `name`, `company`, `email`  FROM `' . TABLE_PANEL_CUSTOMERS . "`
						WHERE `adminid` = :adminid");
					Database::pexecute($result, [
						'adminid' => $userinfo['adminid']
					]);
				}
			} else {
				Response::standardError('norecipientsgiven');
			}

			$subject = Request::post('subject');
			$message = wordwrap(Request::post('message'), 70);

			if (!empty($message)) {
				$mailcounter = 0;
				$mail->Body = $message;
				$mail->Subject = $subject;

				while ($row = $result->fetch(PDO::FETCH_ASSOC)) {
					$row['firstname'] = isset($row['firstname']) ? $row['firstname'] : '';
					$row['company'] = isset($row['company']) ? $row['company'] : '';
					$mail->AddAddress($row['email'], User::getCorrectUserSalutation([
						'firstname' => $row['firstname'],
						'name' => $row['name'],
						'company' => $row['company']
					]));
					$mail->From = $userinfo['email'];
					$mail->FromName = (isset($userinfo['firstname']) ? $userinfo['firstname'] . ' ' : '') . $userinfo['name'];

					if (!$mail->Send()) {
						if ($mail->ErrorInfo != '') {
							$mailerr_msg = $mail->ErrorInfo;
						} else {
							$mailerr_msg = $row['email'];
						}

						$log->logAction(FroxlorLogger::ADM_ACTION, LOG_ERR, 'Error sending mail: ' . $mailerr_msg);
						Response::standardError('errorsendingmail', $row['email']);
					}

					$mailcounter++;
					$mail->ClearAddresses();
				}

				Response::redirectTo($filename, [
					'page' => $page,
					'action' => 'showsuccess',
					'sentitems' => $mailcounter
				]);
			} else {
				Response::standardError('nomessagetosend');
			}
		}
	} elseif ($action == 'showsuccess') {
		$sentitems = Request::get('sentitems', 0);

		if ($sentitems == 0) {
			$note_type = 'info';
			$note_msg = lng('message.norecipients');
		} else {
			$note_type = 'success';
			$note_msg = lng('message.success', [$sentitems]);
		}
	}

	$recipients = [];

	if ($userinfo['customers_see_all'] == '1') {
		$recipients[0] = lng('panel.reseller');
	}
	$recipients[1] = lng('panel.customer');

	$messages_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/messages/formfield.messages_add.php';

	UI::view('user/form-note.html.twig', [
		'formaction' => $linker->getLink(['section' => 'message', 'action' => '']),
		'formdata' => $messages_add_data['messages_add'],
		'actions_links' => ($userinfo['change_serversettings'] == '1' ? [
			[
				'href' => $linker->getLink([
					'section' => 'settings',
					'page' => 'overview',
					'part' => 'system',
					'em' => 'system_mail_use_smtp'
				]),
				'label' => lng('admin.smtpsettings'),
				'icon' => 'fa-solid fa-gears',
				'class' => 'btn-outline-secondary'
			]
		] : []),
		// alert-box
		'type' => $note_type,
		'alert_msg' => $note_msg
	]);
}
