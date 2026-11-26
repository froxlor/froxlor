<?php

use Froxlor\FroxlorTwoFactorAuth;
use PHPUnit\Framework\TestCase;

/**
 *
 * @covers \Froxlor\FroxlorTwoFactorAuth
 */
class TwoFactorEmptySecretTest extends TestCase
{

	public function testEmptySecretNeverVerifies()
	{
		$tfa = new FroxlorTwoFactorAuth('Froxlor test');
		// the code anyone can calculate for an empty secret
		$code = $tfa->getCode('');
		$this->assertFalse($tfa->verifyCode('', $code, 60));
		$this->assertFalse($tfa->verifyCode(' ', $code, 60));
		$this->assertFalse($tfa->verifyCode(null, $code, 60));
	}

	public function testEmptyCodeNeverVerifies()
	{
		$tfa = new FroxlorTwoFactorAuth('Froxlor test');
		$secret = $tfa->createSecret();
		$this->assertFalse($tfa->verifyCode($secret, '', 3));
	}

	public function testValidSecretStillVerifies()
	{
		$tfa = new FroxlorTwoFactorAuth('Froxlor test');
		$secret = $tfa->createSecret();
		$this->assertTrue($tfa->verifyCode($secret, $tfa->getCode($secret), 3));
		$this->assertFalse($tfa->verifyCode($secret, '000000x', 3));
	}
}
