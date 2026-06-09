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

use Exception;
use Froxlor\Cron\Forkable;
use Froxlor\Cron\FroxlorCron;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;

class ExportCron extends FroxlorCron
{
	use Forkable;

	public static function run()
	{
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'ExportCron: started - creating customer data export');

		$result_tasks_stmt = Database::query("
			SELECT * FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '20' ORDER BY `id` ASC
		");
		$all_jobs = $result_tasks_stmt->fetchAll();

		if (!empty($all_jobs)) {
			self::runFork([self::class, 'handle'], $all_jobs);
		}
	}

	public static function handle(array $row)
	{
		$del_stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `id` = :id");
		$cronlog = FroxlorLogger::getInstanceOf();

		if ($row['data'] != '') {
			$row['data'] = json_decode($row['data'], true);
		}

		if (is_array($row['data'])) {
			if (isset($row['data']['customerid']) && isset($row['data']['loginname']) && isset($row['data']['destdir'])) {
				$customerdocroot = FileDir::makeCorrectDir(Settings::Get('system.documentroot_prefix') . '/' . $row['data']['loginname'] . '/');
				$row['data']['destdir'] = FileDir::makeCorrectDir($row['data']['destdir'], $customerdocroot);

				// create folder if not exists
				if (!file_exists($row['data']['destdir']) && $row['data']['destdir'] != '/' && $row['data']['destdir'] != Settings::Get('system.documentroot_prefix') && $row['data']['destdir'] != $customerdocroot) {
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Creating data export destination path for customer: ' . escapeshellarg($row['data']['destdir']));
					FileDir::safe_exec('mkdir -p ' . escapeshellarg($row['data']['destdir']));
				}

				self::createCustomerExport($row['data'], $customerdocroot, $cronlog);
			}
		}

		// remove entry
		Database::pexecute($del_stmt, [
			'id' => $row['id']
		]);
	}

	/**
	 * depending on the give choice, the customers web-data, email-data and databases are being exported
	 *
	 * @param array $data
	 *
	 * @return void
	 *
	 * @throws Exception
	 */
	private static function createCustomerExport($data = null, $customerdocroot = null, &$cronlog = null)
	{
		$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, 'Creating data export for user "' . $data['loginname'] . '"');

		// create tmp folder
		$tmpdir = FileDir::makeCorrectDir($data['destdir'] . '/.tmp/', $customerdocroot);
		$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Creating tmp-folder "' . $tmpdir . '"');
		$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> mkdir -p ' . escapeshellarg($tmpdir));
		FileDir::safe_exec('mkdir -p ' . escapeshellarg($tmpdir));
		$create_export_tar_data = "";

		// MySQL databases
		if ($data['dump_dbs'] == 1) {
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Creating mysql-folder "' . FileDir::makeCorrectDir($tmpdir . '/mysql') . '"');
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> mkdir -p ' . escapeshellarg(FileDir::makeCorrectDir($tmpdir . '/mysql')));
			FileDir::safe_exec('mkdir -p ' . escapeshellarg(FileDir::makeCorrectDir($tmpdir . '/mysql')));

			// get all customer database-names
			$sel_stmt = Database::prepare("SELECT `databasename`, `dbserver` FROM `" . TABLE_PANEL_DATABASES . "` WHERE `customerid` = :cid ORDER BY `dbserver`");
			Database::pexecute($sel_stmt, [
				'cid' => $data['customerid']
			]);

			$has_dbs = false;
			$current_dbserver = -1;

			// look for mysqldump
			$section = 'mysqldump';
			if (file_exists("/usr/bin/mysqldump")) {
				$mysql_dump = '/usr/bin/mysqldump';
			} elseif (file_exists("/usr/local/bin/mysqldump")) {
				$mysql_dump = '/usr/local/bin/mysqldump';
			} elseif (file_exists("/usr/bin/mariadb-dump")) {
				$mysql_dump = '/usr/bin/mariadb-dump';
				$section = 'mariadb-dump';
			}
			if (!isset($mysql_dump)) {
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'mysqldump/mariadb-dump executable could not be found. Please install mysql-client/mariadb-client package.');
			} else {

				while ($row = $sel_stmt->fetch()) {
					// Get sql_root data for the specific database-server the database resides on
					if ($current_dbserver != $row['dbserver']) {
						Database::needRoot(true, $row['dbserver']);
						Database::needSqlData();
						$sql_root = Database::getSqlData();
						Database::needRoot(false);
						// create temporary mysql-defaults file for the connection-credentials/details
						$mysqlcnf_file = tempnam("/tmp", "frx");
						$mysqlcnf = "[".$section."]\npassword=" . $sql_root['passwd'] . "\nhost=" . $sql_root['host'] . "\n";
						if (!empty($sql_root['port'])) {
							$mysqlcnf .= "port=" . $sql_root['port'] . "\n";
						} elseif (!empty($sql_root['socket'])) {
							$mysqlcnf .= "socket=" . $sql_root['socket'] . "\n";
						}
						file_put_contents($mysqlcnf_file, $mysqlcnf);
					}
					$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> '.basename($mysql_dump) . ' -u ' . escapeshellarg($sql_root['user']) . ' -pXXXXX ' . $row['databasename'] . ' > ' . FileDir::makeCorrectFile($tmpdir . '/mysql/' . $row['databasename'] . '_' . date('YmdHi', time()) . '.sql'));
					$bool_false = false;
					FileDir::safe_exec($mysql_dump . ' --defaults-file=' . escapeshellarg($mysqlcnf_file) . ' -u ' . escapeshellarg($sql_root['user']) . ' ' . $row['databasename'] . ' > ' . FileDir::makeCorrectFile($tmpdir . '/mysql/' . $row['databasename'] . '_' . date('YmdHi', time()) . '.sql'), $bool_false, [
						'>'
					]);
					$has_dbs = true;
					$current_dbserver = $row['dbserver'];
				}
			}

			if ($has_dbs) {
				$create_export_tar_data .= './mysql ';
			}

			if (file_exists($mysqlcnf_file)) {
				unlink($mysqlcnf_file);
			}

			unset($sql_root);
		}

		// E-mail data
		if ($data['dump_mail'] == 1) {
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Creating mail-folder "' . FileDir::makeCorrectDir($tmpdir . '/mail') . '"');
			FileDir::safe_exec('mkdir -p ' . escapeshellarg(FileDir::makeCorrectDir($tmpdir . '/mail')));

			// get all customer mail-accounts
			$sel_stmt = Database::prepare("SELECT `homedir`, `maildir` FROM `" . TABLE_MAIL_USERS . "` WHERE `customerid` = :cid");
			Database::pexecute($sel_stmt, [
				'cid' => $data['customerid']
			]);

			$tar_file_list = "";
			$mail_homedir = "";
			while ($row = $sel_stmt->fetch()) {
				$tar_file_list .= escapeshellarg("./" . $row['maildir']) . " ";
				$mail_homedir = $row['homedir'];
			}

			if (!empty($tar_file_list)) {
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> tar cfvz ' . escapeshellarg(FileDir::makeCorrectFile($tmpdir . '/mail/' . $data['loginname'] . '-mail.tar.gz')) . ' -C ' . escapeshellarg($mail_homedir) . ' ' . trim($tar_file_list));
				FileDir::safe_exec('tar cfz ' . escapeshellarg(FileDir::makeCorrectFile($tmpdir . '/mail/' . $data['loginname'] . '-mail.tar.gz')) . ' -C ' . escapeshellarg($mail_homedir) . ' ' . trim($tar_file_list));
				$create_export_tar_data .= './mail ';
			}
		}

		// Web data
		if ($data['dump_web'] == 1) {
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Creating web-folder "' . FileDir::makeCorrectDir($tmpdir . '/web') . '"');
			FileDir::safe_exec('mkdir -p ' . escapeshellarg(FileDir::makeCorrectDir($tmpdir . '/web')));
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> tar cfz ' . escapeshellarg(FileDir::makeCorrectFile($tmpdir . '/web/' . $data['loginname'] . '-web.tar.gz')) . ' --exclude=' . escapeshellarg(str_replace($customerdocroot, "./", FileDir::makeCorrectFile($tmpdir . '/*'))) . ' --exclude=' . escapeshellarg(str_replace($customerdocroot, "./", substr(FileDir::makeCorrectDir($tmpdir), 0, -1))) . ' -C ' . escapeshellarg($customerdocroot) . ' .');
			FileDir::safe_exec('tar cfz ' . escapeshellarg(FileDir::makeCorrectFile($tmpdir . '/web/' . $data['loginname'] . '-web.tar.gz')) . ' --exclude=' . escapeshellarg(str_replace($customerdocroot, "./", FileDir::makeCorrectFile($tmpdir . '/*'))) . ' --exclude=' . escapeshellarg(str_replace($customerdocroot, "./", substr(FileDir::makeCorrectFile($tmpdir), 0, -1))) . ' -C ' . escapeshellarg($customerdocroot) . ' .');
			$create_export_tar_data .= './web ';
		}

		if (!empty($create_export_tar_data)) {
			// set owner to customer
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> chown -R ' . (int)$data['uid'] . ':' . (int)$data['gid'] . ' ' . escapeshellarg($tmpdir));
			FileDir::safe_exec('chown -R ' . (int)$data['uid'] . ':' . (int)$data['gid'] . ' ' . escapeshellarg($tmpdir));
			// create tar-file
			$export_file = FileDir::makeCorrectFile($tmpdir . '/' . $data['loginname'] . '-export_' . date('YmdHi', time()) . '.tar.gz' . (!empty($data['pgp_public_key']) ? '.gpg' : ''));
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Creating export-file "' . $export_file . '"');
			if (!empty($data['pgp_public_key'])) {
				// pack all archives in tmp-dir to one archive and encrypt it with gpg
				$recipient_file = FileDir::makeCorrectFile($tmpdir . '/' . $data['loginname'] . '-recipients.gpg');
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Creating recipient-file "' . $recipient_file . '"');
				file_put_contents($recipient_file, $data['pgp_public_key']);
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> tar cfz - -C ' . escapeshellarg($tmpdir) . ' ' . trim($create_export_tar_data) . ' | gpg --encrypt --recipient-file ' . escapeshellarg($recipient_file) . ' --output ' . escapeshellarg($export_file) . ' --trust-model always --batch --yes');
				FileDir::safe_exec('tar cfz - -C ' . escapeshellarg($tmpdir) . ' ' . trim($create_export_tar_data) . ' | gpg --encrypt --recipient-file ' . escapeshellarg($recipient_file) . ' --output ' . escapeshellarg($export_file) . ' --trust-model always --batch --yes', $return_value, ['|']);
			} else {
				// pack all archives in tmp-dir to one archive
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> tar cfz ' . escapeshellarg($export_file) . ' -C ' . escapeshellarg($tmpdir) . ' ' . trim($create_export_tar_data));
				FileDir::safe_exec('tar cfz ' . escapeshellarg($export_file) . ' -C ' . escapeshellarg($tmpdir) . ' ' . trim($create_export_tar_data));
			}
			// move to destination directory
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> mv ' . escapeshellarg($export_file) . ' ' . escapeshellarg($data['destdir']));
			FileDir::safe_exec('mv ' . escapeshellarg($export_file) . ' ' . escapeshellarg($data['destdir']));
			// remove tmp-files
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> rm -rf ' . escapeshellarg($tmpdir));
			FileDir::safe_exec('rm -rf ' . escapeshellarg($tmpdir));
			// set owner to customer
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> chown -R ' . (int)$data['uid'] . ':' . (int)$data['gid'] . ' ' . escapeshellarg($data['destdir']));
			if (is_link(rtrim($data['destdir'], '/'))) {
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Export destination is a symlink, skipping chown for security: ' . $data['destdir']);
			} else {
				FileDir::safe_exec('chown -R ' . (int)$data['uid'] . ':' . (int)$data['gid'] . ' ' . escapeshellarg($data['destdir']));
			}
		}
	}
}
