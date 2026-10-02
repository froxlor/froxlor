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

namespace Froxlor;

use Froxlor\System\MysqlHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogHandler;
use Monolog\Logger;

/**
 * Class FroxlorLogger
 */
class FroxlorLogger
{

	const USR_ACTION = '10';
	const RES_ACTION = '20';
	const ADM_ACTION = '30';
	const CRON_ACTION = '40';
	const LOGIN_ACTION = '50';
	const LOG_ERROR = '99';
	/**
	 * current \Monolog\Logger object
	 *
	 * @var ?Logger
	 */
	private static ?Logger $ml = null;
	/**
	 * LogTypes Array
	 *
	 * @var ?array
	 */
	private static ?array $logtypes = null;
	/**
	 * whether to output log-messages to STDOUT (cron)
	 *
	 * @var bool
	 */
	private static bool $crondebug_flag = false;
	/**
	 * user info of logged-in user
	 *
	 * @var array
	 */
	private static array $userinfo = [];
	/**
	 * whether the logger object has already been initialized
	 *
	 * @var bool
	 */
	private static bool $is_initialized = false;

	/**
	 * Class constructor.
	 *
	 * @param array $userinfo
	 *
	 * @throws \Exception
	 */
	protected function __construct(array $userinfo = [])
	{
		$this->initMonolog();
		self::$userinfo = $userinfo;
		self::$logtypes = [];

		if ((Settings::Get('logger.logtypes') == null || Settings::Get('logger.logtypes') == '') && (Settings::Get('logger.enabled') !== null && Settings::Get('logger.enabled'))) {
			self::$logtypes[0] = 'syslog';
			self::$logtypes[1] = 'mysql';
		} else {
			if (Settings::Get('logger.logtypes') !== null && Settings::Get('logger.logtypes') != '') {
				self::$logtypes = explode(',', Settings::Get('logger.logtypes'));
			} else {
				self::$logtypes = null;
			}
		}

		if (self::$is_initialized == false) {
			foreach (self::$logtypes as $logger) {
				switch ($logger) {
					case 'syslog':
						self::$ml->pushHandler(new SyslogHandler('froxlor', LOG_USER, Logger::DEBUG));
						break;
					case 'file':
						$setings_logfile = Settings::Get('logger.logfile');
						if (empty($setings_logfile)) {
							Settings::Set('logger.logfile', 'froxlor.log');
						}
						$logger_logfile = FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/logs/' . Settings::Get('logger.logfile'));
						// is_writable needs an existing file to check if it's actually writable
						if (!@touch($logger_logfile) || !is_writable($logger_logfile)) {
							// not writable in our own directory? Skip
							break;
						}
						self::$ml->pushHandler(new StreamHandler($logger_logfile, Logger::DEBUG));
						break;
					case 'mysql':
						self::$ml->pushHandler(new MysqlHandler(Logger::DEBUG));
						break;
				}
			}
			self::$is_initialized = true;
		}
	}

	/**
	 * initiate monolog object
	 *
	 * @return Logger
	 */
	private function initMonolog()
	{
		if (empty(self::$ml)) {
			// get Theme object
			self::$ml = new Logger('froxlor');
		}
		return self::$ml;
	}

	/**
	 * return FroxlorLogger instance
	 *
	 * @param array $userinfo
	 *
	 * @return FroxlorLogger
	 * @throws \Exception
	 */
	public static function getInstanceOf(array $userinfo = [])
	{
		if (empty($userinfo)) {
			$userinfo = [
				'loginname' => 'system'
			];
		}
		return new FroxlorLogger($userinfo);
	}

	/**
	 * logs a given text to all enabled logger-facilities
	 *
	 * @param int $action
	 * @param int $type
	 * @param ?string $text
	 */
	public function logAction($action = FroxlorLogger::USR_ACTION, int $type = LOG_NOTICE, ?string $text = null)
	{
		// not logging normal stuff if not set to "paranoid" logging
		if (!self::$crondebug_flag && Settings::Get('logger.severity') == '1' && $type > LOG_NOTICE) {
			return;
		}

		if (empty(self::$ml)) {
			$this->initMonolog();
		}

		// clean log-text
		$text = preg_replace("/[^\w @#\"':.,()\[\]+\-_\/\\\!]/i", "_", $text);

		if (self::$crondebug_flag || ($action == FroxlorLogger::CRON_ACTION && $type <= LOG_WARNING)) {
			echo "[" . $this->getLogLevelDesc($type) . "] " . $text . PHP_EOL;
		}

		// warnings, errors and critical messages WILL be logged
		if (Settings::Get('logger.log_cron') == '0' && $action == FroxlorLogger::CRON_ACTION && $type > LOG_WARNING) {
			return;
		}

		$logExtra = [
			'source' => $this->getActionTypeDesc($action),
			'action' => $action,
			'user' => self::$userinfo['loginname']
		];

		switch ($type) {
			case LOG_DEBUG:
				self::$ml->addDebug($text, $logExtra);
				break;
			case LOG_INFO:
				self::$ml->addInfo($text, $logExtra);
				break;
			case LOG_NOTICE:
				self::$ml->addNotice($text, $logExtra);
				break;
			case LOG_WARNING:
				self::$ml->addWarning($text, $logExtra);
				break;
			case LOG_ERR:
				self::$ml->addError($text, $logExtra);
				break;
			default:
				self::$ml->addDebug($text, $logExtra);
		}
	}

	/**
	 * @param int $type
	 * @return string
	 */
	public function getLogLevelDesc(int $type): string
	{
		switch ($type) {
			case LOG_INFO:
				$_type = 'information';
				break;
			case LOG_NOTICE:
				$_type = 'notice';
				break;
			case LOG_WARNING:
				$_type = 'warning';
				break;
			case LOG_ERR:
				$_type = 'error';
				break;
			case LOG_CRIT:
				$_type = 'critical';
				break;
			case LOG_DEBUG:
				$_type = 'debug';
				break;
			default:
				$_type = 'unknown';
				break;
		}
		return $_type;
	}

	/**
	 * @param $action
	 * @return string
	 */
	private function getActionTypeDesc($action): string
	{
		switch ($action) {
			case FroxlorLogger::USR_ACTION:
				$_action = 'user';
				break;
			case FroxlorLogger::ADM_ACTION:
				$_action = 'admin';
				break;
			case FroxlorLogger::RES_ACTION:
				$_action = 'reseller';
				break;
			case FroxlorLogger::CRON_ACTION:
				$_action = 'cron';
				break;
			case FroxlorLogger::LOGIN_ACTION:
				$_action = 'login';
				break;
			default:
				$_action = 'unknown';
				break;
		}
		return $_action;
	}

	/**
	 * Set whether to log cron-runs
	 *
	 * @param int $cronlog
	 *
	 * @return int
	 */
	public function setCronLog(int $cronlog = 0): int
	{
		if ($cronlog < 0 || $cronlog > 2) {
			$cronlog = 0;
		}
		Settings::Set('logger.log_cron', $cronlog);
		return $cronlog;
	}

	/**
	 * setter for crondebug-flag
	 *
	 * @param bool $flag
	 *
	 * @return void
	 */
	public function setCronDebugFlag(bool $flag = false)
	{
		self::$crondebug_flag = $flag;
	}
}
