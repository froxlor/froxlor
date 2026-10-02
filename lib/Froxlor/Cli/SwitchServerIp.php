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

namespace Froxlor\Cli;

use Froxlor\Database\Database;
use PDO;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class SwitchServerIp extends CliCommand
{

	protected function configure()
	{
		$this->setName('froxlor:switch-server-ip');
		$this->setDescription('Easily switch IP addresses e.g. after server migration');
		$this->addOption('switch', 's', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Switch IP-address pair. A pair is separated by comma. For example: --switch=A,B')
			->addOption('list', 'l', InputOption::VALUE_NONE, 'List all IP addresses currently added for this server in froxlor');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$result = $this->validateRequirements($output);

		if ($result == self::SUCCESS && $input->getOption('list') == false && $input->getOption('switch') == false) {
			$output->writeln('<error>Either --list or --switch option must be provided. Nothing to do, exiting.</>');
			$result = self::INVALID;
		}

		$io = new SymfonyStyle($input, $output);

		if ($result == self::SUCCESS && $input->getOption('list')) {
			$sel_stmt = Database::prepare("SELECT * FROM panel_ipsandports ORDER BY ip ASC, port ASC");
			Database::pexecute($sel_stmt);
			$ips = $sel_stmt->fetchAll(PDO::FETCH_ASSOC);
			$table_rows = [];
			foreach ($ips as $ipdata) {
				$table_rows[] = [$ipdata['id'], $ipdata['ip'], $ipdata['port']];
			}

			$io->table(
				['#', 'IP address', 'Port'],
				$table_rows
			);
		}

		if ($result == self::SUCCESS && $input->getOption('switch')) {
			$result = $this->switchIPs($input, $output);
		}

		return $result;
	}

	private function switchIPs(InputInterface $input, OutputInterface $output): int
	{
		$ip_list = $input->getOption('switch');

		$has_error = false;
		$ips_to_switch = [];
		foreach ($ip_list as $ips_combo) {
			$ip_pair = explode(",", $ips_combo);
			if (count($ip_pair) != 2) {
				$output->writeln('<error>Invalid option parameter, not a valid IP address pair.</>');
				$has_error = true;
			} else {
				if (filter_var($ip_pair[0], FILTER_VALIDATE_IP) == false) {
					$output->writeln('<error>Invalid source ip address: ' . $ip_pair[0] . '</>');
					$has_error = true;
				}
				if (filter_var($ip_pair[1], FILTER_VALIDATE_IP) == false) {
					$output->writeln('<error>Invalid target ip address: ' . $ip_pair[1] . '</>');
					$has_error = true;
				}
				if ($ip_pair[0] == $ip_pair[1] && !$has_error) {
					$output->writeln('<error>Source and target ip address are equal</>');
					$has_error = true;
				}
			}
			$ips_to_switch[] = $ip_pair;
		}
		if ($has_error) {
			return self::FAILURE;
		}

		if (count($ips_to_switch) > 0) {
			$check_stmt = Database::prepare("SELECT `id` FROM panel_ipsandports WHERE `ip` = :newip");
			$upd_stmt = Database::prepare("UPDATE panel_ipsandports SET `ip` = :newip WHERE `ip` = :oldip");

			// system.ipaddress
			$check_sysip_stmt = Database::prepare("SELECT `value` FROM `panel_settings` WHERE `settinggroup` = 'system' and `varname` = 'ipaddress'");
			$check_sysip = Database::pexecute_first($check_sysip_stmt);

			// system.mysql_access_host
			$check_mysqlip_stmt = Database::prepare("SELECT `value` FROM `panel_settings` WHERE `settinggroup` = 'system' and `varname` = 'mysql_access_host'");
			$check_mysqlip = Database::pexecute_first($check_mysqlip_stmt);

			// system.axfrservers
			$check_axfrip_stmt = Database::prepare("SELECT `value` FROM `panel_settings` WHERE `settinggroup` = 'system' and `varname` = 'axfrservers'");
			$check_axfrip = Database::pexecute_first($check_axfrip_stmt);

			foreach ($ips_to_switch as $ip_pair) {
				$output->writeln('Switching IP <comment>' . $ip_pair[0] . '</> to IP <comment>' . $ip_pair[1] . '</>');

				$ip_check = Database::pexecute_first($check_stmt, [
					'newip' => $ip_pair[1]
				]);
				if ($ip_check) {
					$output->writeln('<error>Note: ' . $ip_pair[0] . ' not updated to ' . $ip_pair[1] . ' - IP already exists in froxlor\'s database</>');
					continue;
				}

				Database::pexecute($upd_stmt, [
					'newip' => $ip_pair[1],
					'oldip' => $ip_pair[0]
				]);
				$rows_updated = $upd_stmt->rowCount();

				if ($rows_updated == 0) {
					$output->writeln('<error>Note: ' . $ip_pair[0] . ' not updated to ' . $ip_pair[1] . ' (possibly no entry found in froxlor database. Use --list to see what IP addresses are added in froxlor');
					continue;
				}

				// check whether the system.ipaddress needs updating
				if ($check_sysip['value'] == $ip_pair[0]) {
					$upd2_stmt = Database::prepare("UPDATE `panel_settings` SET `value` = :newip WHERE `settinggroup` = 'system' and `varname` = 'ipaddress'");
					Database::pexecute($upd2_stmt, [
						'newip' => $ip_pair[1]
					]);
					$output->writeln('<info>Updated system-ipaddress from <comment>' . $ip_pair[0] . '</comment> to <comment>' . $ip_pair[1] . '</comment></info>');
				}

				// check whether the system.mysql_access_host needs updating
				if (strstr($check_mysqlip['value'], $ip_pair[0]) !== false) {
					$new_mysqlip = str_replace($ip_pair[0], $ip_pair[1], $check_mysqlip['value']);
					$upd2_stmt = Database::prepare("UPDATE `panel_settings` SET `value` = :newmysql WHERE `settinggroup` = 'system' and `varname` = 'mysql_access_host'");
					Database::pexecute($upd2_stmt, [
						'newmysql' => $new_mysqlip
					]);
					$output->writeln('<info>Updated mysql_access_host from <comment>' . $check_mysqlip['value'] . '</comment> to <comment>' . $new_mysqlip . '</comment></info>');
				}

				// check whether the system.axfrservers needs updating
				if (strstr($check_axfrip['value'], $ip_pair[0]) !== false) {
					$new_axfrip = str_replace($ip_pair[0], $ip_pair[1], $check_axfrip['value']);
					$upd2_stmt = Database::prepare("UPDATE `panel_settings` SET `value` = :newaxfr WHERE `settinggroup` = 'system' and `varname` = 'axfrservers'");
					Database::pexecute($upd2_stmt, [
						'newaxfr' => $new_axfrip
					]);
					$output->writeln('<info>Updated axfr-servers from <comment>' . $check_axfrip['value'] . '</comment> to <comment>' . $new_axfrip . '</comment></info>');
				}
			}
		}

		$output->writeln("");
		$output->writeln("<comment>*** ATTENTION *** Remember to replace IP addresses in configuration files if used anywhere.</>");
		$output->writeln("<info>IP addresses updated</>");
		return self::SUCCESS;
	}
}
