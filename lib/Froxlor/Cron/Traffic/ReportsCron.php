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

namespace Froxlor\Cron\Traffic;

/**
 * @author        Florian Lippert <flo@syscp.org> (2003-2009)
 * @author        Froxlor team <team@froxlor.org> (2010-)
 */

use Exception;
use Froxlor\Cron\FroxlorCron;
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Mailer;
use Froxlor\User;
use Froxlor\Language;
use PDO;

class ReportsCron extends FroxlorCron
{

	public static function run()
	{
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Web- and Traffic-usage reporting started...');
		$yesterday = time() - (60 * 60 * 24);

		/**
		 * Initialize the mailingsystem
		 */
		$mail = new Mailer(true);

		// set default language before anything else to
		// ensure that we can display messages
		Language::setLanguage(Settings::Get('panel.standardlanguage'));

		if ((int)Settings::Get('system.report_trafficmax') > 0) {
			// Warn the customers at xx% traffic-usage
			$result_stmt = Database::prepare("
				SELECT `c`.`customerid`, `c`.`loginname`, `c`.`customernumber`, `c`.`adminid`, `c`.`name`, `c`.`firstname`,
				`c`.`company`, `c`.`traffic`, `c`.`email`, `c`.`def_language`,
				`a`.`name` AS `adminname`, `a`.`email` AS `adminmail`,
				(SELECT SUM(`t`.`http` + `t`.`ftp_up` + `t`.`ftp_down` + `t`.`mail`)
				FROM `" . TABLE_PANEL_TRAFFIC . "` `t`
				WHERE `t`.`customerid` = `c`.`customerid` AND `t`.`year` = :year AND `t`.`month` = :month
				) as `traffic_used`
				FROM `" . TABLE_PANEL_CUSTOMERS . "` AS `c`
				LEFT JOIN `" . TABLE_PANEL_ADMINS . "` AS `a`
				ON `a`.`adminid` = `c`.`adminid` WHERE `c`.`reportsent` & 1 = 0
			");

			$result_data = [
				'year' => date("Y", $yesterday),
				'month' => date("m", $yesterday)
			];
			Database::pexecute($result_stmt, $result_data);

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `reportsent` = `reportsent` + 1
				WHERE `customerid` = :customerid
			");

			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$row['traffic'] *= 1024;
				$row['traffic_used'] *= 1024;
				if (isset($row['traffic']) && $row['traffic'] > 0 && $row['traffic_used'] != null && (($row['traffic_used'] * 100) / $row['traffic']) >= (int)Settings::Get('system.report_trafficmax')) {
					$rep_userinfo = [
						'name' => $row['name'],
						'firstname' => $row['firstname'],
						'company' => $row['company'],
						'loginname' => $row['loginname'],
						'customernumber' => $row['customernumber']
					];
					$replace_arr = [
						'SALUTATION' => User::getCorrectUserSalutation($rep_userinfo),
						'NAME' => $rep_userinfo['name'],
						'FIRSTNAME' => $rep_userinfo['firstname'],
						'COMPANY' => $rep_userinfo['company'],
						'USERNAME' => $rep_userinfo['loginname'],
						'CUSTOMER_NO' => $rep_userinfo['customernumber'],
						'TRAFFIC' => PhpHelper::sizeReadable((int)$row['traffic'], null, 'bi'),
						'TRAFFICUSED' => PhpHelper::sizeReadable((int)$row['traffic_used'], null, 'bi'),
						'USAGE_PERCENT' => round(($row['traffic_used'] * 100) / $row['traffic'], 2),
						'MAX_PERCENT' => Settings::Get('system.report_trafficmax')
					];

					// set target user language
					Language::setLanguage($row['def_language']);

					// Get mail templates from database; the ones from 'admin' are fetched for fallback
					$result2_stmt = Database::prepare("
						SELECT `value` FROM `" . TABLE_PANEL_TEMPLATES . "`
						WHERE `adminid` = :adminid
						AND `language` = :lang
						AND `templategroup` = 'mails' AND `varname` = :varname
					");
					$result2_data = [
						'adminid' => $row['adminid'],
						'lang' => $row['def_language'],
						'varname' => 'trafficmaxpercent_subject'
					];
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_subject = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.trafficmaxpercent.subject')), $replace_arr));

					$result2_data['varname'] = 'trafficmaxpercent_mailbody';
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_body = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.trafficmaxpercent.mailbody')), $replace_arr));

					$_mailerror = false;
					$mailerr_msg = "";
					try {
						$mail->setFrom(Settings::Get('panel.adminmail'), $row['adminname']);
						$mail->clearReplyTos();
						$mail->addReplyTo($row['adminmail'], $row['adminname']);
						$mail->Subject = $mail_subject;
						$mail->AltBody = $mail_body;
						$mail->MsgHTML(nl2br($mail_body));
						$mail->AddAddress($row['email'], $row['firstname'] . ' ' . $row['name']);
						$mail->Send();
					} catch (\PHPMailer\PHPMailer\Exception $e) {
						$mailerr_msg = $e->errorMessage();
						$_mailerror = true;
					} catch (Exception $e) {
						$mailerr_msg = $e->getMessage();
						$_mailerror = true;
					}

					if ($_mailerror) {
						FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Error sending mail: ' . $mailerr_msg);
						echo 'Error sending mail: ' . $mailerr_msg . "\n";
					}

					$mail->ClearAddresses();
					Database::pexecute($upd_stmt, [
						'customerid' => $row['customerid']
					]);
				}
			}

			// Warn the admins at xx% traffic-usage
			$result_stmt = Database::prepare("
				SELECT `a`.*,
				(SELECT SUM(`t`.`http` + `t`.`ftp_up` + `t`.`ftp_down` + `t`.`mail`)
				FROM `" . TABLE_PANEL_TRAFFIC_ADMINS . "` `t`
				WHERE `t`.`adminid` = `a`.`adminid` AND `t`.`year` = :year AND `t`.`month` = :month
				) as `traffic_used_total`
				FROM `" . TABLE_PANEL_ADMINS . "` `a` WHERE `a`.`reportsent` & 1 = 0
			");

			$result_data = [
				'year' => date("Y", $yesterday),
				'month' => date("m", $yesterday)
			];
			Database::pexecute($result_stmt, $result_data);

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_ADMINS . "` SET `reportsent` = `reportsent` + 1
				WHERE `adminid` = :adminid
			");

			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$row['traffic'] *= 1024;
				$row['traffic_used_total'] *= 1024;
				if (isset($row['traffic']) && $row['traffic'] > 0 && (($row['traffic_used_total'] * 100) / ($row['traffic'])) >= (int)Settings::Get('system.report_trafficmax')) {
					$replace_arr = [
						'NAME' => $row['name'],
						'TRAFFIC' => PhpHelper::sizeReadable((int)$row['traffic'], null, 'bi'),
						'TRAFFICUSED' => PhpHelper::sizeReadable((int)$row['traffic_used_total'], null, 'bi'),
						'USAGE_PERCENT' => round(($row['traffic_used_total'] * 100) / $row['traffic'], 2),
						'MAX_PERCENT' => Settings::Get('system.report_trafficmax')
					];

					// set target user language
					Language::setLanguage($row['def_language']);

					// Get mail templates from database; the ones from 'admin' are fetched for fallback
					$result2_stmt = Database::prepare("
						SELECT `value` FROM `" . TABLE_PANEL_TEMPLATES . "`
						WHERE `adminid` = :adminid
						AND `language` = :lang
						AND `templategroup` = 'mails' AND `varname` = :varname
					");
					$result2_data = [
						'adminid' => $row['adminid'],
						'lang' => $row['def_language'],
						'varname' => 'trafficmaxpercent_subject'
					];
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_subject = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.trafficmaxpercent.subject')), $replace_arr));

					$result2_data['varname'] = 'trafficmaxpercent_mailbody';
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_body = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.trafficmaxpercent.mailbody')), $replace_arr));

					$_mailerror = false;
					$mailerr_msg = "";
					try {
						$mail->SetFrom(Settings::Get('panel.adminmail'), Settings::Get('panel.adminmail_defname'));
						$mail->Subject = $mail_subject;
						$mail->AltBody = $mail_body;
						$mail->MsgHTML(nl2br($mail_body));
						$mail->AddAddress($row['email'], $row['name']);
						$mail->Send();
					} catch (\PHPMailer\PHPMailer\Exception $e) {
						$mailerr_msg = $e->errorMessage();
						$_mailerror = true;
					} catch (Exception $e) {
						$mailerr_msg = $e->getMessage();
						$_mailerror = true;
					}

					if ($_mailerror) {
						FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, "Error sending mail: " . $mailerr_msg);
						echo "Error sending mail: " . $mailerr_msg . "\n";
					}

					$mail->ClearAddresses();
					Database::pexecute($upd_stmt, [
						'adminid' => $row['adminid']
					]);
				}

				// Another month, let's build our report
				if (date('d') == '01') {
					$mail_subject = 'Trafficreport ' . date("m/y", $yesterday) . ' for ' . $row['name'];
					$mail_body = 'Trafficreport ' . date("m/y", $yesterday) . ' for ' . $row['name'] . "\n";
					$mail_body .= '---------------------------------------------------------------' . "\n";
					$mail_body .= 'Loginname       Traffic used  (Percent) | Traffic available' . "\n";
					$customers_stmt = Database::prepare("
						SELECT `c`.*,
						(SELECT SUM(`t`.`http` + `t`.`ftp_up` + `t`.`ftp_down` + `t`.`mail`)
						FROM `" . TABLE_PANEL_TRAFFIC . "` `t`
						WHERE `t`.`customerid` = `c`.`customerid` AND `t`.`year` = :year AND `t`.`month` = :month
						) as `traffic_used_total`
						FROM `" . TABLE_PANEL_CUSTOMERS . "` `c` WHERE `c`.`adminid` = :adminid
					");
					$customers_data = [
						'year' => date("Y", $yesterday),
						'month' => date("m", $yesterday),
						'adminid' => $row['adminid']
					];
					Database::pexecute($customers_stmt, $customers_data);

					while ($customer = $customers_stmt->fetch(PDO::FETCH_ASSOC)) {
						$customer['traffic'] *= 1024;
						$t = (int) $customer['traffic_used_total'] * 1024;
						if ($customer['traffic'] > 0) {
							$p = (($t * 100) / $customer['traffic']);
							$tg = (int) $customer['traffic'];
							$str = sprintf('%s  ( %00.1f %% )', PhpHelper::sizeReadable($t, null, 'bi'), $p);
							$mail_body .= sprintf('%-15s', $customer['loginname']) . ' ' . sprintf('%-25s', $str) . ' ' . sprintf('%s', PhpHelper::sizeReadable($tg, null, 'bi')) . "\n";
						} elseif ($customer['traffic'] == 0) {
							$str = sprintf('%s  (   -   )', PhpHelper::sizeReadable($t, null, 'bi'));
							$mail_body .= sprintf('%-15s', $customer['loginname']) . ' ' . sprintf('%-25s', $str) . ' ' . '0' . "\n";
						} else {
							$str = sprintf('%s  (   -   )', PhpHelper::sizeReadable($t, null, 'bi'));
							$mail_body .= sprintf('%-15s', $customer['loginname']) . ' ' . sprintf('%-25s', $str) . ' ' . 'unlimited' . "\n";
						}
					}

					$mail_body .= '---------------------------------------------------------------' . "\n";

					$t = (int) $row['traffic_used_total'];
					if ($row['traffic'] > 0) {
						$p = (($t * 100) / $row['traffic']);
						$tg = (int) $row['traffic'];
						$str = sprintf('%s  ( %00.1f %% )', PhpHelper::sizeReadable($t, null, 'bi'), $p);
						$mail_body .= sprintf('%-15s', $row['loginname']) . ' ' . sprintf('%-25s', $str) . ' ' . sprintf('%s', PhpHelper::sizeReadable($tg, null, 'bi')) . "\n";
					} elseif ($row['traffic'] == 0) {
						$str = sprintf('%s  (   -   )', PhpHelper::sizeReadable($t, null, 'bi'));
						$mail_body .= sprintf('%-15s', $row['loginname']) . ' ' . sprintf('%-25s', $str) . ' ' . '0' . "\n";
					} else {
						$str = sprintf('%s  (   -   )', PhpHelper::sizeReadable($t, null, 'bi'));
						$mail_body .= sprintf('%-15s', $row['loginname']) . ' ' . sprintf('%-25s', $str) . ' ' . 'unlimited' . "\n";
					}

					$_mailerror = false;
					$mailerr_msg = "";
					try {
						$mail->SetFrom(Settings::Get('panel.adminmail'), Settings::Get('panel.adminmail_defname'));
						$mail->Subject = $mail_subject;
						$mail->Body = $mail_body;
						$mail->MsgHTML(nl2br($mail_body));
						$mail->AddAddress($row['email'], $row['name']);
						$mail->Send();
					} catch (\PHPMailer\PHPMailer\Exception $e) {
						$mailerr_msg = $e->errorMessage();
						$_mailerror = true;
					} catch (Exception $e) {
						$mailerr_msg = $e->getMessage();
						$_mailerror = true;
					}

					if ($_mailerror) {
						FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Error sending mail: ' . $mailerr_msg);
						echo 'Error sending mail: ' . $mailerr_msg . "\n";
					}

					$mail->ClearAddresses();
				}
			}
		} // trafficmax > 0

		// include diskspace-usage report, #466
		self::usageDiskspace();

		// Another month, reset the reportstatus
		if (date('d') == '01') {
			Database::query("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `reportsent` = '0';");
			Database::query("UPDATE `" . TABLE_PANEL_ADMINS . "` SET `reportsent` = '0';");
		}
	}

	private static function usageDiskspace()
	{
		if ((int)Settings::Get('system.report_webmax') > 0) {
			/**
			 * report about diskusage for customers
			 */
			$result_stmt = Database::query("
				SELECT `c`.`customerid`, `c`.`loginname`, `c`.`customernumber`, `c`.`adminid`, `c`.`name`, `c`.`firstname`,
				`c`.`company`, `c`.`diskspace`, `c`.`diskspace_used`, `c`.`email`, `c`.`def_language`,
				`a`.`name` AS `adminname`, `a`.`email` AS `adminmail`
				FROM `" . TABLE_PANEL_CUSTOMERS . "` AS `c`
			    LEFT JOIN `" . TABLE_PANEL_ADMINS . "` AS `a`
			    ON `a`.`adminid` = `c`.`adminid`
			    WHERE `c`.`diskspace` > '0' AND `c`.`reportsent` & 2 = 0
			");

			$mail = new Mailer(true);

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `reportsent` = `reportsent` + 2
				WHERE `customerid` = :customerid
			");

			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$row['diskspace'] *= 1024;
				$row['diskspace_used'] *= 1024;
				if (isset($row['diskspace']) && $row['diskspace_used'] != null && $row['diskspace_used'] > 0 && (($row['diskspace_used'] * 100) / $row['diskspace']) >= (int)Settings::Get('system.report_webmax')) {
					$rep_userinfo = [
						'name' => $row['name'],
						'firstname' => $row['firstname'],
						'company' => $row['company'],
						'loginname' => $row['loginname'],
						'customernumber' => $row['customernumber']
					];
					$replace_arr = [
						'SALUTATION' => User::getCorrectUserSalutation($rep_userinfo),
						'NAME' => $rep_userinfo['name'],
						'FIRSTNAME' => $rep_userinfo['firstname'],
						'COMPANY' => $rep_userinfo['company'],
						'USERNAME' => $rep_userinfo['loginname'],
						'CUSTOMER_NO' => $rep_userinfo['customernumber'],
						'DISKAVAILABLE' => PhpHelper::sizeReadable((int)$row['diskspace'], null, 'bi'),
						'DISKUSED' => PhpHelper::sizeReadable((int)$row['diskspace_used'], null, 'bi'),
						'USAGE_PERCENT' => round(($row['diskspace_used'] * 100) / $row['diskspace'], 2),
						'MAX_PERCENT' => Settings::Get('system.report_webmax')
					];

					// set target user language
					Language::setLanguage($row['def_language']);

					// Get mail templates from database; the ones from 'admin' are fetched for fallback
					$result2_stmt = Database::prepare("
						SELECT `value` FROM `" . TABLE_PANEL_TEMPLATES . "`
						WHERE `adminid` = :adminid
						AND `language` = :lang
						AND `templategroup` = 'mails' AND `varname` = :varname
					");
					$result2_data = [
						'adminid' => $row['adminid'],
						'lang' => $row['def_language'],
						'varname' => 'diskmaxpercent_subject'
					];
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_subject = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.diskmaxpercent.subject')), $replace_arr));

					$result2_data['varname'] = 'diskmaxpercent_mailbody';
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_body = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.diskmaxpercent.mailbody')), $replace_arr));

					$_mailerror = false;
					$mailerr_msg = "";
					try {
						$mail->setFrom(Settings::Get('panel.adminmail'), $row['adminname']);
						$mail->clearReplyTos();
						$mail->addReplyTo($row['adminmail'], $row['adminname']);
						$mail->Subject = $mail_subject;
						$mail->AltBody = $mail_body;
						$mail->MsgHTML(nl2br($mail_body));
						$mail->AddAddress($row['email'], $row['name']);
						if (Settings::Get('system.report_web_bccadmin')) {
							$mail->addBCC(Settings::Get('panel.adminmail'), $row['adminname']);
						}
						$mail->Send();
					} catch (\PHPMailer\PHPMailer\Exception $e) {
						$mailerr_msg = $e->errorMessage();
						$_mailerror = true;
					} catch (Exception $e) {
						$mailerr_msg = $e->getMessage();
						$_mailerror = true;
					}

					if ($_mailerror) {
						FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, "Error sending mail: " . $mailerr_msg);
						echo "Error sending mail: " . $mailerr_msg . "\n";
					}

					$mail->ClearAddresses();
					Database::pexecute($upd_stmt, [
						'customerid' => $row['customerid']
					]);
				}
			}

			/**
			 * report about diskusage for admins/reseller
			 */
			$result_stmt = Database::query("
				SELECT `a`.* FROM `" . TABLE_PANEL_ADMINS . "` `a` WHERE `a`.`reportsent` & 2 = 0
			");

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_ADMINS . "` SET `reportsent` = `reportsent` + 2
				WHERE `adminid` = :adminid
			");

			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$row['diskspace'] *= 1024;
				$row['diskspace_used'] *= 1024;
				if (isset($row['diskspace']) && $row['diskspace_used'] != null && $row['diskspace_used'] > 0 && (($row['diskspace_used'] * 100) / $row['diskspace']) >= (int)Settings::Get('system.report_webmax')) {
					$replace_arr = [
						'NAME' => $row['name'],
						'DISKAVAILABLE' => PhpHelper::sizeReadable((int)$row['diskspace'], null, 'bi'),
						'DISKUSED' => PhpHelper::sizeReadable((int)$row['diskspace_used'], null, 'bi'),
						'USAGE_PERCENT' => ($row['diskspace_used'] * 100) / $row['diskspace'],
						'MAX_PERCENT' => Settings::Get('system.report_webmax')
					];

					// set target user language
					Language::setLanguage($row['def_language']);

					// Get mail templates from database; the ones from 'admin' are fetched for fallback
					$result2_stmt = Database::prepare("
						SELECT `value` FROM `" . TABLE_PANEL_TEMPLATES . "`
						WHERE `adminid` = :adminid
						AND `language` = :lang
						AND `templategroup` = 'mails' AND `varname` = :varname
					");
					$result2_data = [
						'adminid' => $row['adminid'],
						'lang' => $row['def_language'],
						'varname' => 'diskmaxpercent_subject'
					];
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_subject = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.diskmaxpercent.subject')), $replace_arr));

					$result2_data['varname'] = 'diskmaxpercent_mailbody';
					$result2 = Database::pexecute_first($result2_stmt, $result2_data);
					$mail_body = html_entity_decode(PhpHelper::replaceVariables((($result2 !== false && $result2['value'] != '') ? $result2['value'] : Language::getTranslation('mails.diskmaxpercent.mailbody')), $replace_arr));

					$_mailerror = false;
					$mailerr_msg = "";
					try {
						$mail->SetFrom(Settings::Get('panel.adminmail'), Settings::Get('panel.adminmail_defname'));
						$mail->Subject = $mail_subject;
						$mail->AltBody = $mail_body;
						$mail->MsgHTML(nl2br($mail_body));
						$mail->AddAddress($row['email'], $row['name']);
						$mail->Send();
					} catch (\PHPMailer\PHPMailer\Exception $e) {
						$mailerr_msg = $e->errorMessage();
						$_mailerror = true;
					} catch (Exception $e) {
						$mailerr_msg = $e->getMessage();
						$_mailerror = true;
					}

					if ($_mailerror) {
						FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, "Error sending mail: " . $mailerr_msg);
						echo "Error sending mail: " . $mailerr_msg . "\n";
					}

					$mail->ClearAddresses();
					Database::pexecute($upd_stmt, [
						'adminid' => $row['adminid']
					]);
				}
			}
		} // webmax > 0
	}
}
