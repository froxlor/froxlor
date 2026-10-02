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

use Exception;
use Froxlor\Config\ConfigParser;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\SImExporter;
use Froxlor\System\Crypt;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class ConfigServices extends CliCommand
{
	private $yes_to_all_supported = [
		'trixie',
		'bookworm',
		'bullseye',
		'focal',
		'jammy',
		'noble',
	];

	protected function configure()
	{
		$this->setName('froxlor:config-services');
		$this->setDescription('Configure system services');
		$this->addOption('create', 'c', InputOption::VALUE_NONE, 'Create a services list configuration for the --apply option.')
			->addOption('apply', 'a', InputOption::VALUE_REQUIRED, 'Configure your services by given configuration file/string. To create one run the command with the --create option.')
			->addOption('list', 'l', InputOption::VALUE_NONE, 'Output the services that are going to be configured using a given config file (--apply option). No services will be configured.')
			->addOption('daemon', 'd', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'When used with --apply you can specify one or multiple daemons. These will be the only services that get configured.')
			->addOption('import-settings', 'i', InputOption::VALUE_REQUIRED, 'Import settings from another froxlor installation. This can be done standalone or in addition to --apply.')
			->addOption('yes-to-all', 'A', InputOption::VALUE_NONE, 'Install packages without asking questions (Debian/Ubuntu only currently)')
			->addOption('delete-file', 'D', InputOption::VALUE_NONE, 'If --apply is called with a local file, remove it after successful configurations.');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$result = $this->validateRequirements($output);

		require Froxlor::getInstallDir() . '/lib/functions.php';

		if ($result == self::SUCCESS && $input->getOption('import-settings') == false && $input->getOption('create') == false && $input->getOption('apply') == false) {
			$output->writeln('<error>No option given to do something, exiting.</>');
			return self::INVALID;
		}

		// import settings if given
		if ($result == self::SUCCESS && $input->getOption('import-settings')) {
			$result = $this->importSettings($input, $output);
		}

		if ($result == self::SUCCESS && $input->getOption('yes-to-all')) {
			if (in_array(Settings::Get('system.distribution'), $this->yes_to_all_supported)) {
				putenv("DEBIAN_FRONTEND=noninteractive");
				exec("echo 'APT::Get::Assume-Yes \"true\";' > /tmp/_tmp_apt.conf");
				putenv("APT_CONFIG=/tmp/_tmp_apt.conf");
			} else {
				$output->writeln('<comment>--yes-to-all ignored, not configured for supported distribution</>');
			}
		}

		if ($result == self::SUCCESS) {
			$io = new SymfonyStyle($input, $output);
			if ($input->getOption('create')) {
				$result = $this->createConfig($output, $io);
			} elseif ($input->getOption('apply')) {
				$result = $this->applyConfig($input, $output, $io);
			} elseif ($input->getOption('list') || $input->getOption('daemon')) {
				$output->writeln('<error>Options --list and --daemon only work together with --apply.</>');
				$result = self::INVALID;
			}
		}

		if ($input->getOption('yes-to-all') && in_array(Settings::Get('system.distribution'), $this->yes_to_all_supported)) {
			putenv("DEBIAN_FRONTEND");
			unlink("/tmp/_tmp_apt.conf");
			putenv("APT_CONFIG");
		}

		return $result;
	}

	private function importSettings(InputInterface $input, OutputInterface $output)
	{
		$importFile = $input->getOption('import-settings');

		if (strtoupper(substr($importFile, 0, 4)) == 'HTTP') {
			$output->writeln("Settings file seems to be an URL, trying to download");
			$target = "/tmp/froxlor-import-settings-" . time() . ".json";
			if (@file_exists($target)) {
				@unlink($target);
			}
			$this->downloadFile($importFile, $target);
			$importFile = $target;
		}
		if (!is_file($importFile)) {
			$output->writeln('<error>Given settings file is not a file</>');
			return self::INVALID;
		} elseif (!file_exists($importFile)) {
			$output->writeln('<error>Given settings file cannot be found (' . $importFile . ')</>');
			return self::INVALID;
		} elseif (!is_readable($importFile)) {
			$output->writeln('<error>Given settings file cannot be read (' . $importFile . ')</>');
			return self::INVALID;
		}
		$imp_content = file_get_contents($importFile);
		SImExporter::import($imp_content);
		$output->writeln("<info>Successfully imported settings from '" . $input->getOption('import-settings') . "'</info>");
		return self::SUCCESS;
	}

	private function downloadFile($src, $dest)
	{
		set_time_limit(0);
		// This is the file where we save the information
		$fp = fopen($dest, 'w+');
		// Here is the file we are downloading, replace spaces with %20
		$ch = curl_init(str_replace(" ", "%20", $src));
		curl_setopt($ch, CURLOPT_TIMEOUT, 50);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		// write curl response to file
		curl_setopt($ch, CURLOPT_FILE, $fp);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		// get curl response
		curl_exec($ch);
		fclose($fp);
	}

	/**
	 * @throws Exception
	 */
	private function createConfig(OutputInterface $output, SymfonyStyle $io): int
	{
		$_daemons_config = [
			'distro' => ""
		];

		$config_dir = Froxlor::getInstallDir() . '/lib/configfiles/';
		// show list of available distro's
		$distros = glob($config_dir . '*.xml');
		// tmp array
		$distributions_select_data = [];

		//set default os.
		$os_dist = ['ID' => 'trixie'];
		$os_version = ['0' => '13'];
		$os_default = $os_dist['ID'];

		//read os-release
		if (file_exists('/etc/os-release')) {
			$os_dist = parse_ini_file('/etc/os-release', false);
			if (is_array($os_dist) && array_key_exists('ID', $os_dist) && array_key_exists('VERSION_ID', $os_dist)) {
				$os_version = explode('.', $os_dist['VERSION_ID'])[0];
			}
		}

		// read in all the distros
		foreach ($distros as $_distribution) {
			// get configparser object
			$dist = new ConfigParser($_distribution);
			// get distro-info
			$dist_display = $dist->getCompleteDistroName();
			// store in tmp array
			$distributions_select_data[$dist_display] = str_replace(".xml", "", strtolower(basename($_distribution)));

			//guess if this is the current distro.
			$ver = explode('.', $dist->distributionVersion)[0];
			if (strtolower($os_dist['ID']) == strtolower($dist->distributionName) && $os_version == $ver) {
				$os_default = str_replace(".xml", "", strtolower(basename($_distribution)));
			}
		}

		// sort by distribution name
		ksort($distributions_select_data);

		// list all distributions
		$table_rows = [];
		$valid_dists = [];
		foreach ($distributions_select_data as $name => $filename) {
			$table_rows[] = [$filename, $name];
			$valid_dists[] = $filename;
		}
		$io->table(
			['ID', 'Distribution'],
			$table_rows
		);

		$_daemons_config['distro'] = $io->choice('Choose distribution', $valid_dists, $os_default);

		// go through all services and let user check whether to include it or not
		if (empty($_daemons_config['distro']) || !file_exists($config_dir . '/' . $_daemons_config['distro'] . ".xml")) {
			$output->writeln('<error>Empty or non-existing distribution given.</>');
			return self::INVALID;
		}
		$configfiles = new ConfigParser($config_dir . '/' . $_daemons_config['distro'] . ".xml");
		$services = $configfiles->getServices();

		foreach ($services as $si => $service) {
			$output->writeln("--- " . strtoupper($si) . " ---");
			$_daemons_config[$si] = "";

			$daemons = $service->getDaemons();
			$default_daemon = "";
			$table_rows = [];
			$valid_options = [];
			if ($si != 'system') {
				$table_rows[] = ['x', 'No'];
				$valid_options[] = 'x';
			}
			foreach ($daemons as $di => $dd) {
				$title = $dd->title;
				if ($dd->default) {
					$default_daemon = $di;
					$title .= " (default)";
				}
				$table_rows[] = [$di, $title];
				$valid_options[] = $di;
			}
			$io->table(
				['Value', 'Name'],
				$table_rows
			);

			$daemons['x'] = 'x';
			if ($si == 'system') {
				$_daemons_config[$si] = [];
				// for the system/other services we need a multiple choice possibility
				$output->writeln("<comment>Select every service you need. Enter empty value when done</>");
				$sysservice = "";
				do {
					$sysservice = $io->ask('Choose service');
					if (!empty($sysservice)) {
						$_daemons_config[$si][] = $sysservice;
					}
				} while (!empty($sysservice));
				// add 'cron' as fixed part (doesn't hurt if it exists)
				if (!in_array('cron', $_daemons_config[$si])) {
					$_daemons_config[$si][] = 'cron';
				}
			} else {
				// for all others -> only one value
				$_daemons_config[$si] = $io->choice('Choose service', $valid_options, $default_daemon);
			}
		}

		$daemons_config = json_encode($_daemons_config);
		$output_file = $io->ask("Choose output-filename", "/tmp/froxlor-config-" . date('Ymd') . ".json");
		file_put_contents($output_file, $daemons_config);
		$output->writeln("<info>Successfully generated service-configfile '" . $output_file . "'</>");
		$output->writeln([
			"",
			"<info>You can now apply this config running:</>",
			"php " . Froxlor::getInstallDir() . "bin/froxlor-cli froxlor:config-services --apply=" . $output_file,
			""
		]);
		$proceed = $io->confirm("Do you want to apply the config now?", false);
		if ($proceed) {
			passthru("php " . Froxlor::getInstallDir() . "bin/froxlor-cli froxlor:config-services --apply=" . $output_file);
		}
		return self::SUCCESS;
	}

	/**
	 * @throws Exception
	 */
	private function applyConfig(InputInterface $input, OutputInterface $output, SymfonyStyle $io): int
	{
		$applyFile = $input->getOption('apply');

		// check if plain JSON
		$decoded_config = json_decode($applyFile, true);
		$skipFileCheck = false;
		if (json_last_error() == JSON_ERROR_NONE) {
			$skipFileCheck = true;
		}

		if (!$skipFileCheck) {
			if (strtoupper(substr($applyFile, 0, 4)) == 'HTTP') {
				$output->writeln("Config file seems to be an URL, trying to download");
				$target = "/tmp/froxlor-config-" . time() . ".json";
				if (@file_exists($target)) {
					@unlink($target);
				}
				$this->downloadFile($applyFile, $target);
				$applyFile = $target;
			}
			if (!is_file($applyFile)) {
				$output->writeln('<error>Given config file is not a file</>');
				return self::INVALID;
			} elseif (!file_exists($applyFile)) {
				$output->writeln('<error>Given config file cannot be found (' . $applyFile . ')</>');
				return self::INVALID;
			} elseif (!is_readable($applyFile)) {
				$output->writeln('<error>Given config file cannot be read (' . $applyFile . ')</>');
				return self::INVALID;
			}

			$config = file_get_contents($applyFile);
			$decoded_config = json_decode($config, true);
		}

		if ($input->getOption('list') != false) {
			$table_rows = [];
			foreach ($decoded_config as $service => $daemon) {
				if (is_array($daemon) && count($daemon) > 0) {
					foreach ($daemon as $sysdaemon) {
						$table_rows[] = [$service, $sysdaemon];
					}
				} else {
					if ($daemon == 'x') {
						$daemon = '--- skipped ---';
					}
					$table_rows[] = [$service, $daemon];
				}
			}

			$io->table(
				['Service', 'Selected daemon'],
				$table_rows
			);
			return self::SUCCESS;
		}

		$only_daemon = [];
		if ($input->getOption('daemon') != false) {
			$only_daemon = $input->getOption('daemon');
		}

		if (!empty($decoded_config)) {

			$config_dir = Froxlor::getInstallDir() . 'lib/configfiles/';
			if (empty($decoded_config['distro']) || !file_exists($config_dir . '/' . $decoded_config['distro'] . ".xml")) {
				$output->writeln('<error>Empty or non-existing distribution given. Please login with an admin, go to "System -> Configuration" and select your correct distribution in the top-right corner or specify valid distribution name for "distro" parameter.</>');
				return self::INVALID;
			}
			$configfiles = new ConfigParser($config_dir . '/' . $decoded_config['distro'] . ".xml");
			$services = $configfiles->getServices();
			$replace_arr = $this->getReplacerArray();
			$clean_replace_arr = array_map(function ($v) {
				return escapeshellarg((string)($v ?? ''));
			}, $replace_arr);

			// be sure the fallback certificate specified in the settings exists
			$certFile = Settings::Get('system.ssl_cert_file');
			$keyFile = Settings::Get('system.ssl_key_file');
			if (empty($certFile) || empty($keyFile) || !file_exists($certFile) || !file_exists($keyFile)) {
				$output->writeln('<comment>Creating missing certificate ' . $certFile . '</>');
				Crypt::createSelfSignedCertificate();
			}

			foreach ($services as $si => $service) {
				$output->writeln("--- Configuring: " . strtoupper($si) . " ---");
				if (!isset($decoded_config[$si]) || $decoded_config[$si] == 'x') {
					$output->writeln('<comment>Skipping ' . strtoupper($si) . ' configuration as desired</>');
					continue;
				}
				$daemons = $service->getDaemons();
				foreach ($daemons as $di => $dd) {
					// check for desired service
					if (($si != 'system' && $decoded_config[$si] != $di) || (is_array($decoded_config[$si]) && !in_array($di, $decoded_config[$si]))) {
						continue;
					}
					$output->writeln("Configuring '" . $di . "'");

					if (!empty($only_daemon) && !in_array($di, $only_daemon)) {
						$output->writeln('<comment>Skipping ' . $di . ' configuration as desired</>');
						continue;
					}
					// run all cmds
					$confarr = $dd->getConfig();
					foreach ($confarr as $action) {
						switch ($action['type']) {
							case "install":
								$output->writeln("Installing required packages");
								$result = null;
								passthru(strtr($action['content'], $clean_replace_arr), $result);
								if (strlen($result) > 1) {
									echo $result;
								}
								break;
							case "command":
								exec(strtr($action['content'], $clean_replace_arr));
								break;
							case "file":
								if (array_key_exists('content', $action)) {
									$output->writeln('<comment>Creating file "' . $action['name'] . '"</>');
									file_put_contents($action['name'], trim(strtr($action['content'], $replace_arr)) . PHP_EOL);
								} elseif (array_key_exists('subcommands', $action)) {
									foreach ($action['subcommands'] as $fileaction) {
										if (array_key_exists('execute', $fileaction) && $fileaction['execute'] == "pre") {
											exec(strtr($fileaction['content'], $replace_arr));
										} elseif (array_key_exists('execute', $fileaction) && $fileaction['execute'] == "post") {
											exec(strtr($fileaction['content'], $replace_arr));
										} elseif ($fileaction['type'] == 'file') {
											$output->writeln('<comment>Creating file "' . $fileaction['name'] . '"</>');
											file_put_contents($fileaction['name'], trim(strtr($fileaction['content'], $replace_arr)) . PHP_EOL);
										}
									}
								}
								break;
						}
					}
				}
			}
			// set is_configured flag
			Settings::Set('panel.is_configured', '1', true);
			// run cronjob at the end to ensure configs are all up to date
			exec('php ' . Froxlor::getInstallDir() . 'bin/froxlor-cli froxlor:cron --force');
			// and done
			$output->writeln('<info>All services have been configured</>');

			if ($input->getOption('delete-file') && file_exists($applyFile)) {
				@unlink($applyFile);
			}
			return self::SUCCESS;
		} else {
			$output->writeln('<error>Unable to decode given JSON file</>');
			return self::INVALID;
		}
	}

	/**
	 * @throws Exception
	 */
	private function getReplacerArray(): array
	{
		$customer_tmpdir = '/tmp/';
		if (Settings::Get('system.mod_fcgid') == '1' && Settings::Get('system.mod_fcgid_tmpdir') != '') {
			$customer_tmpdir = Settings::Get('system.mod_fcgid_tmpdir');
		} elseif (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.tmpdir') != '') {
			$customer_tmpdir = Settings::Get('phpfpm.tmpdir');
		}

		// try to convert nameserver hosts to ip's
		$ns_ips = "";
		$known_ns_ips = [];
		if (Settings::Get('system.nameservers') != '') {
			$nameservers = explode(',', Settings::Get('system.nameservers'));
			foreach ($nameservers as $nameserver) {
				$nameserver = trim($nameserver);
				// DNS servers might be multi homed; allow transfer from all ip
				// addresses of the DNS server
				$nameserver_ips = PhpHelper::gethostbynamel6($nameserver);
				// append dot to hostname
				if (substr($nameserver, -1, 1) != '.') {
					$nameserver .= '.';
				}
				// ignore invalid responses
				if (!is_array($nameserver_ips)) {
					// act like PhpHelper::gethostbynamel6() and return unmodified hostname on error
					$nameserver_ips = [
						$nameserver
					];
				} else {
					$known_ns_ips = array_merge($known_ns_ips, $nameserver_ips);
				}
				if (!empty($ns_ips)) {
					$ns_ips .= ',';
				}
				$ns_ips .= implode(",", $nameserver_ips);
			}
		}

		// AXFR server
		if (Settings::Get('system.axfrservers') != '') {
			$axfrservers = explode(',', Settings::Get('system.axfrservers'));
			foreach ($axfrservers as $axfrserver) {
				if (!in_array(trim($axfrserver), $known_ns_ips)) {
					if (!empty($ns_ips)) {
						$ns_ips .= ',';
					}
					$ns_ips .= trim($axfrserver);
				}
			}
		}

		Database::needSqlData();
		$sql = Database::getSqlData();

		return [
			'<SQL_UNPRIVILEGED_USER>' => $sql['user'],
			'<SQL_UNPRIVILEGED_PASSWORD>' => $sql['passwd'],
			'<SQL_DB>' => $sql['db'],
			'<SQL_HOST>' => $sql['host'],
			'<SQL_SOCKET>' => $sql['socket'] ?? null,
			'<SERVERNAME>' => Settings::Get('system.hostname'),
			'<SERVERIP>' => Settings::Get('system.ipaddress'),
			'<NAMESERVERS>' => Settings::Get('system.nameservers'),
			'<NAMESERVERS_IP>' => $ns_ips,
			'<VIRTUAL_MAILBOX_BASE>' => Settings::Get('system.vmail_homedir'),
			'<VIRTUAL_UID_MAPS>' => Settings::Get('system.vmail_uid'),
			'<VIRTUAL_GID_MAPS>' => Settings::Get('system.vmail_gid'),
			'<SSLPROTOCOLS>' => (Settings::Get('system.use_ssl') == '1') ? 'imaps pop3s' : '',
			'<CUSTOMER_TMP>' => FileDir::makeCorrectDir($customer_tmpdir),
			'<BASE_PATH>' => Froxlor::getInstallDir(),
			'<BIND_CONFIG_PATH>' => FileDir::makeCorrectDir(Settings::Get('system.bindconf_directory')),
			'<WEBSERVER_RELOAD_CMD>' => Settings::Get('system.apachereload_command'),
			'<CUSTOMER_LOGS>' => FileDir::makeCorrectDir(Settings::Get('system.logfiles_directory')),
			'<FPM_IPCDIR>' => FileDir::makeCorrectDir(Settings::Get('phpfpm.fastcgi_ipcdir')),
			'<WEBSERVER_GROUP>' => Settings::Get('system.httpgroup'),
			'<SSL_CERT_FILE>' => Settings::Get('system.ssl_cert_file'),
			'<SSL_KEY_FILE>' => Settings::Get('system.ssl_key_file'),
			'<ADMIN_MAIL>' => Settings::Get('panel.adminmail'),
		];
	}
}
