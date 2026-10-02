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
 * @author     Janos Muzsi <muzsij@hypernics.hu>
 * @author     Ralf Becker <beckerr@php.net>
 * @author     Rasmus Lerdorf <rasmus@php.net>
 * @author     Ilia Alshanetsky <ilia@prohost.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 *
 * Based on https://github.com/krakjoe/apcu/blob/master/apc.php, which is
 * licensed under the PHP licence (version 3.01), which can be viewed
 * online at https://www.php.net/license/3_01.txt
 */

use Froxlor\FroxlorLogger;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\UI\HTML;

const AREA = 'admin';
require __DIR__ . '/lib/init.php';

$horizontal_bar_size = 950; // 1280px window width

if ($action == 'delete' && function_exists('apcu_clear_cache') && $userinfo['change_serversettings'] == '1') {
	if (Request::post('send') == 'send') {
		apcu_clear_cache();
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "cleared APCu cache");
		header('Location: ' . $linker->getLink([
				'section' => 'apcuinfo',
				'page' => 'showinfo'
			]));
		exit();
	} else {
		HTML::askYesNo('cache_reallydelete', $filename, [
			'page' => $page,
			'action' => 'delete',
		], '', [
			'section' => 'apcuinfo',
			'page' => 'showinfo'
		]);
	}
}

if (!function_exists('apcu_cache_info') || !function_exists('apcu_sma_info')) {
	Response::standardError('no_apcuinfo');
}

if ($page == 'showinfo' && $userinfo['change_serversettings'] == '1') {
	$cache = apcu_cache_info();
	$mem = apcu_sma_info();
	$time = time();
	$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_apcuinfo");

	// check for possible empty values that are used in the templates
	if (!isset($cache['file_upload_progress'])) {
		$cache['file_upload_progress'] = lng('logger.unknown');
	}

	if (!isset($cache['num_expunges'])) {
		$cache['num_expunges'] = lng('logger.unknown');
	}

	$overview = [
		'mem_size' => $mem['num_seg'] * $mem['seg_size'],
		'mem_avail' => $mem['avail_mem'],
		'mem_used' => ($mem['num_seg'] * $mem['seg_size']) - $mem['avail_mem'],
		'seg_size' => bsize($mem['seg_size']),
		'num_hits' => $cache['num_hits'],
		'num_misses' => $cache['num_misses'],
		'num_inserts' => $cache['num_inserts'],
		'req_rate_user' => sprintf("%.2f",
			$cache['num_hits'] ? (($cache['num_hits'] + $cache['num_misses']) / ($time - $cache['start_time'])) : 0),
		'hit_rate_user' => sprintf("%.2f",
			$cache['num_hits'] ? (($cache['num_hits']) / ($time - $cache['start_time'])) : 0),
		'miss_rate_user' => sprintf("%.2f",
			$cache['num_misses'] ? (($cache['num_misses']) / ($time - $cache['start_time'])) : 0),
		'insert_rate_user' => sprintf("%.2f",
			$cache['num_inserts'] ? (($cache['num_inserts']) / ($time - $cache['start_time'])) : 0),
		'apcversion' => phpversion('apcu'),
		'phpversion' => phpversion(),
		'number_vars' => $cache['num_entries'],
		'size_vars' => bsize($cache['mem_size']),
		'num_hits_and_misses' => 0 >= ($cache['num_hits'] + $cache['num_misses']) ? 1 : ($cache['num_hits'] + $cache['num_misses']),
		'file_upload_progress' => $cache['file_upload_progress'],
		'num_expunges' => $cache['num_expunges'],
		'host' => (function_exists('gethostname')
			? gethostname()
			: (php_uname('n')
				?: (empty($_SERVER['SERVER_NAME'])
					? $_SERVER['HOST_NAME']
					: $_SERVER['SERVER_NAME']
				)
			)
		),
		'server' => $_SERVER['SERVER_SOFTWARE'] ?: '',
		'start_time' => $cache['start_time'],
		'uptime' => duration($cache['start_time'])
	];

	$overview['mem_used_percentage'] = number_format(($overview['mem_used'] / $overview['mem_size']) * 100, 1);
	$overview['num_hits_percentage'] = number_format(($overview['num_hits'] / $overview['num_hits_and_misses']) * 100,
		1);
	$overview['num_misses_percentage'] = number_format(($overview['num_misses'] / $overview['num_hits_and_misses']) * 100,
		1);
	$overview['readable'] = [
		'mem_size' => bsize($overview['mem_size']),
		'mem_avail' => bsize($overview['mem_avail']),
		'mem_used' => bsize($overview['mem_used']),
		'num_hits' => number_format($overview['num_hits']),
		'num_misses' => number_format($overview['num_misses']),
		'number_vars' => number_format($overview['number_vars']),
	];

	$overview['runtimelines'] = [];
	foreach (ini_get_all('apcu') as $name => $v) {
		$value = $v['local_value'];
		$overview['runtimelines'][$name] = $value;
	}

	// Fragementation: (freeseg - 1) / total_seg
	$nseg = $freeseg = $fragsize = $freetotal = 0;
	for ($i = 0; $i < $mem['num_seg']; $i++) {
		$ptr = 0;
		foreach ($mem['block_lists'][$i] as $block) {
			if ($block['offset'] != $ptr) {
				++$nseg;
			}
			$ptr = $block['offset'] + $block['size'];
			/* Only consider blocks <5M for the fragmentation % */
			if ($block['size'] < (5 * 1024 * 1024)) {
				$fragsize += $block['size'];
			}
			$freetotal += $block['size'];
		}
		$freeseg += count($mem['block_lists'][$i]);
	}

	$overview['fragmentation'] = [];
	if ($freeseg > 1) {
		$overview['fragmentation']['used_percentage'] = number_format(($fragsize / $freetotal) * 100, 1);
		$overview['fragmentation']['used_bytes'] = $fragsize;
		$overview['fragmentation']['total_bytes'] = $freetotal;
		$overview['fragmentation']['num_frags'] = $freeseg;
		$overview['fragmentation']['readable'] = [
			'used_bytes' => bsize($fragsize),
			'total_bytes' => bsize($freetotal),
			'num_frags' => number_format($freeseg)
		];
	} else {
		$overview['fragmentation'] = 0;
	}

	UI::view('settings/apcuinfo.html.twig', [
		'apcuinfo' => $overview
	]);
}
// pretty printer for byte values
function bsize($size)
{
	$i = 0;
	$val = ['b', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
	while (($size / 1024) > 1) {
		$size /= 1024;
		++$i;
	}
	return sprintf(
		'%.2f%s%s',
		$size,
		'',
		$val[$i]
	);
}

function duration($ts)
{
	global $time;
	$years = (int)((($time - $ts) / (7 * 86400)) / 52.177457);
	$rem = (int)(($time - $ts) - ($years * 52.177457 * 7 * 86400));
	$weeks = (int)(($rem) / (7 * 86400));
	$days = (int)(($rem) / 86400) - $weeks * 7;
	$hours = (int)(($rem) / 3600) - $days * 24 - $weeks * 7 * 24;
	$mins = (int)(($rem) / 60) - $hours * 60 - $days * 24 * 60 - $weeks * 7 * 24 * 60;
	$str = '';
	if ($years == 1) {
		$str .= "$years year, ";
	}
	if ($years > 1) {
		$str .= "$years years, ";
	}
	if ($weeks == 1) {
		$str .= "$weeks week, ";
	}
	if ($weeks > 1) {
		$str .= "$weeks weeks, ";
	}
	if ($days == 1) {
		$str .= "$days day,";
	}
	if ($days > 1) {
		$str .= "$days days,";
	}
	if ($hours == 1) {
		$str .= " $hours hour and";
	}
	if ($hours > 1) {
		$str .= " $hours hours and";
	}
	if ($mins == 1) {
		$str .= " 1 minute";
	} else {
		$str .= " $mins minutes";
	}
	return $str;
}
