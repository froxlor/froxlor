<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Database\Database;

/**
 * regression test for a 2fa "remember this device" bypass: admin- and customer-ids are
 * separate numeric namespaces that can collide (e.g. both id 1), but panel_2fa_tokens used
 * to only store the bare id, so the remember-cookie lookup in index.php (`selector` +
 * `userid`, no account-type check) let a customer's remembered token satisfy an admin's
 * TOTP step whenever their ids matched. Fixed by adding an `admin` column and scoping every
 * insert/select/delete against panel_2fa_tokens by it, mirroring the existing
 * panel_activation.admin pattern used for password-reset codes.
 *
 * @covers \Froxlor\Froxlor
 */
class TwoFactorRememberTokenTest extends TestCase
{
	public function testRememberTokenDoesNotCrossAdminCustomerNamespace()
	{
		Database::query("DELETE FROM `" . TABLE_PANEL_2FA_TOKENS . "`");

		$selector = 'regressiontestselector';
		$token = hash('sha256', 'regressiontesttoken');

		// a token issued to customer id 1 (as index.php's insert now does, with admin = 0)
		$ins_stmt = Database::prepare("
			INSERT INTO `" . TABLE_PANEL_2FA_TOKENS . "` SET
			`selector` = :selector,
			`token` = :token,
			`userid` = :userid,
			`admin` = :isadmin,
			`valid_until` = :valid_until
		");
		Database::pexecute($ins_stmt, [
			'selector' => $selector,
			'token' => $token,
			'userid' => 1,
			'isadmin' => 0,
			'valid_until' => time() + 3600
		]);

		// the exact lookup index.php performs on the remember-cookie path
		$sel_stmt = Database::prepare("SELECT `token` FROM `" . TABLE_PANEL_2FA_TOKENS . "` WHERE `selector` = :selector AND `userid` = :uid AND `admin` = :isadmin AND `valid_until` >= UNIX_TIMESTAMP()");

		// admin id 1 (the colliding id, different namespace) must NOT match the customer's token
		$admin_match = Database::pexecute_first($sel_stmt, [
			'selector' => $selector,
			'uid' => 1,
			'isadmin' => 1
		]);
		$this->assertFalse($admin_match);

		// customer id 1 (the account the token was actually issued to) must still match
		$customer_match = Database::pexecute_first($sel_stmt, [
			'selector' => $selector,
			'uid' => 1,
			'isadmin' => 0
		]);
		$this->assertEquals($token, $customer_match['token']);
	}
}
