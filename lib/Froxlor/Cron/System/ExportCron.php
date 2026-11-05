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
				try {
					$row['data']['destdir'] = FileDir::makeCorrectDir($row['data']['destdir'], $customerdocroot);
				} catch (Exception $e) {
					// remove the job as well, the customer would otherwise block it forever
					$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Export destination is unsafe, skipping export for security: ' . $e->getMessage());
					Database::pexecute($del_stmt, ['id' => $row['id']]);
					return;
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

		// create tmp folder - this must not be within the customer's docroot: everything below is
		// written (and later chown'ed/removed) as root, and the customer could swap a folder in their
		// own docroot for a symlink while the export is running. The documentroot-prefix (parent of
		// all customer docroots) is root-owned, so we create a private staging folder there (resolved,
		// as the prefix itself may be a symlink, e.g. to a data-disk)
		$tmpparent = realpath(rtrim(FileDir::makeCorrectDir(Settings::Get('system.documentroot_prefix')), '/'));
		$tmpparent_stat = $tmpparent !== false ? @stat($tmpparent) : false;
		if ($tmpparent_stat === false || !is_dir($tmpparent) || $tmpparent_stat['uid'] !== 0 || ($tmpparent_stat['mode'] & 0022) !== 0) {
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Export staging parent "' . Settings::Get('system.documentroot_prefix') . '" must be a root-owned directory not writable by group/others, aborting export for security');
			return;
		}
		$tmpdir = FileDir::makeCorrectDir($tmpparent . '/.froxlor-export-' . $data['loginname'] . '-' . bin2hex(random_bytes(8)));
		$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Creating tmp-folder "' . $tmpdir . '"');
		if (!@mkdir($tmpdir, 0700)) {
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Could not create export staging folder "' . $tmpdir . '", aborting export');
			return;
		}
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
			// don't include the export destination folder (and with it previous exports)
			$exclude_destdir = '';
			$destdir_rel = trim(substr($data['destdir'], strlen($customerdocroot)), '/');
			if ($destdir_rel != '') {
				$exclude_destdir = ' --exclude=' . escapeshellarg('./' . $destdir_rel);
			}
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> tar cfz ' . escapeshellarg(FileDir::makeCorrectFile($tmpdir . '/web/' . $data['loginname'] . '-web.tar.gz')) . $exclude_destdir . ' -C ' . escapeshellarg($customerdocroot) . ' .');
			FileDir::safe_exec('tar cfz ' . escapeshellarg(FileDir::makeCorrectFile($tmpdir . '/web/' . $data['loginname'] . '-web.tar.gz')) . $exclude_destdir . ' -C ' . escapeshellarg($customerdocroot) . ' .');
			$create_export_tar_data .= './web ';
		}

		if (!empty($create_export_tar_data)) {
			// note: the staging folder and its content stay root-owned
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
			// re-validate the destination immediately before writing to it: a path component
			// could have been swapped for a symlink after this job was scheduled, or even while
			// the dump above was running
			try {
				FileDir::makeCorrectDir($data['destdir'], $customerdocroot);
			} catch (Exception $e) {
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Export destination is unsafe, aborting export for security: ' . $e->getMessage());
				FileDir::safe_exec('rm -rf ' . escapeshellarg($tmpdir));
				return;
			}
			// any component can still be swapped right after that check, so the destination is
			// only ever touched with the permissions of the customer
			$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Storing export-file in ' . escapeshellarg($data['destdir']));
			if (!self::storeExportAsCustomer($export_file, $data['destdir'], $data['loginname'], (int)$data['uid'], (int)$data['gid'])) {
				$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Could not store export-file in "' . $data['destdir'] . '" with permissions of customer "' . $data['loginname'] . '"');
			}
		}
		// remove tmp-files
		$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'shell> rm -rf ' . escapeshellarg($tmpdir));
		FileDir::safe_exec('rm -rf ' . escapeshellarg($tmpdir));
	}

	/**
	 * Creates the destination folder (if required) and copies the export-file into it with the
	 * effective user/groups of the customer. The destination is fully controlled by the customer,
	 * running this as customer means the kernel enforces that it can only end up where the
	 * customer is allowed to write anyway - no matter which symlinks are being swapped in.
	 *
	 * @param string $export_file root-owned source file
	 * @param string $destdir
	 * @param string $loginname
	 * @param int $uid
	 * @param int $gid
	 *
	 * @return bool
	 */
	private static function storeExportAsCustomer(string $export_file, string $destdir, string $loginname, int $uid, int $gid): bool
	{
		// open and stat the source now, the customer has no access to the staging folder
		$source = @fopen($export_file, 'rb');
		$export_size = filesize($export_file);
		if ($source === false || $export_size === false || $uid <= 0 || $gid <= 0) {
			return false;
		}

		$stored = false;
		try {
			if (posix_initgroups($loginname, $gid) && posix_setegid($gid) && posix_seteuid($uid)) {
				if (is_dir($destdir) || @mkdir($destdir, 0755, true)) {
					$target = FileDir::makeCorrectFile($destdir . '/' . basename($export_file));
					// 'x' fails if the target exists, also if it is a (dangling) symlink
					$destination = @fopen($target, 'xb');
					if ($destination !== false) {
						$stored = stream_copy_to_stream($source, $destination) === $export_size;
						$stored = fclose($destination) && $stored;
						if (!$stored) {
							@unlink($target);
						}
					}
				}
			}
		} finally {
			// failing to get back to root must never result in continuing as the wrong user
			if (!posix_seteuid(0) || !posix_setegid(0) || !posix_initgroups('root', 0)) {
				exit(1);
			}
			fclose($source);
		}
		return $stored;
	}
}
