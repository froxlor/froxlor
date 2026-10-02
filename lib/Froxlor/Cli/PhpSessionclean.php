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
use Froxlor\FileDir;
use Froxlor\Settings;
use PDO;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class PhpSessionclean extends CliCommand
{

	protected function configure()
	{
		$this->setName('froxlor:php-sessionclean');
		$this->setDescription('Cleans old php-session files from tmp folder');
		$this->addArgument('max-lifetime', InputArgument::OPTIONAL, 'The number of seconds after which data will be seen as "garbage" and potentially cleaned up. Defaults to "1440"');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$result = $this->validateRequirements($output);

		if ($result == self::SUCCESS) {
			if ((int)Settings::Get('phpfpm.enabled') == 1) {
				if ($input->hasArgument('max-lifetime') && is_numeric($input->getArgument('max-lifetime')) && $input->getArgument('max-lifetime') > 0) {
					$this->cleanSessionfiles((int)$input->getArgument('max-lifetime'));
				} else {
					// use default max-lifetime value
					$this->cleanSessionfiles();
				}
				$result = self::SUCCESS;
			} else {
				// php-fpm not enabled
				$output->writeln('<comment>PHP-FPM not enabled for this installation.</comment>');
				$result = self::INVALID;
			}
		}
		return $result;
	}

	private function cleanSessionfiles(int $maxlifetime = 1440)
	{
		// store paths to clean up
		$paths_to_clean = [];
		// get all pool-config directories configured
		$sel_stmt = Database::prepare("SELECT DISTINCT `config_dir` FROM `" . TABLE_PANEL_FPMDAEMONS . "`");
		Database::pexecute($sel_stmt);
		while ($fpmd = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
			$poolfiles = glob(FileDir::makeCorrectFile($fpmd['config_dir'] . '/*.conf'));
			foreach ($poolfiles as $cf) {
				$contents = file_get_contents($cf);
				$pattern = preg_quote('session.save_path', '/');
				$pattern = "/" . $pattern . ".+?\=(.*)/";
				if (preg_match_all($pattern, $contents, $matches)) {
					$session_path = trim($matches[1][0]);
					// Skip non-file-based session storage (Redis, Memcached, etc.)
					// These typically contain protocol indicators like :// or are not valid directories
					if (strpos($session_path, '://') !== false) {
						// Skip paths with protocol indicators (tcp://, redis://, memcached://, etc.)
						continue;
					}
					$paths_to_clean[] = FileDir::makeCorrectDir(trim($matches[1][0]));
				}
			}
		}

		// every path is just needed once
		$paths_to_clean = array_unique($paths_to_clean);

		if (count($paths_to_clean) > 0) {
			foreach ($paths_to_clean as $ptc) {
				// find all files older than maxlifetime and delete them
				FileDir::safe_exec("find -O3 \"" . $ptc . "\" -ignore_readdir_race -depth -mindepth 1 -name 'sess_*' -type f -cmin \"+" . $maxlifetime . "\" -delete");
			}
		}
	}
}
