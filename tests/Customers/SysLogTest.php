<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Database\Database;
use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\SysLog;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\Commands\SysLog
 */
class SysLogTest extends TestCase
{

	public function testResellerSysLogSearchAndTruncateKeepTheUserCondition()
	{
		global $admin_userdata;
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		// let the reseller own test1 for this test
		$stmt = Database::prepare("SELECT `adminid` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `loginname` = 'test1'");
		$owner = Database::pexecute_first($stmt)['adminid'];
		$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `adminid` = :aid WHERE `loginname` = 'test1'");
		Database::pexecute($stmt, ['aid' => $reseller_userdata['adminid']]);

		Database::query("DELETE FROM `" . TABLE_PANEL_LOG . "`");
		$ins = Database::prepare("INSERT INTO `" . TABLE_PANEL_LOG . "` SET `user` = :user, `text` = :text, `date` = :date");
		Database::pexecute($ins, ['user' => 'reseller', 'text' => 'reseller row', 'date' => time()]);
		Database::pexecute($ins, ['user' => 'test1', 'text' => 'recent customer row', 'date' => time()]);
		Database::pexecute($ins, ['user' => 'test1', 'text' => 'old customer row', 'date' => time() - 7200]);

		$json_result = SysLog::getLocal($reseller_userdata, [
			'sql_search' => [
				'text' => [
					'value' => 'customer row',
					'op' => null /* LIKE */
				]
			]
		])->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(['old customer row', 'recent customer row'], $this->texts($result['list']));

		// truncating requires change_serversettings (like admin_logger.php does)
		try {
			SysLog::getLocal($reseller_userdata, ['min_to_keep' => 10])->delete();
			$this->fail('SysLog.delete must not be allowed without change_serversettings');
		} catch (\PHPUnit\Framework\AssertionFailedError $e) {
			throw $e;
		} catch (\Exception $e) {
			$this->assertEquals(403, $e->getCode());
		}

		$reseller_userdata['change_serversettings'] = 1;
		SysLog::getLocal($reseller_userdata, ['min_to_keep' => 10])->delete();
		$rows = Database::query("SELECT `text` FROM `" . TABLE_PANEL_LOG . "` WHERE `text` LIKE '% row'")->fetchAll(\PDO::FETCH_ASSOC);
		$this->assertEquals(['recent customer row', 'reseller row'], $this->texts($rows));

		Database::pexecute($stmt, ['aid' => $owner]);
	}

	private function texts(array $rows): array
	{
		$texts = array_column($rows, 'text');
		sort($texts);
		return $texts;
	}
}
