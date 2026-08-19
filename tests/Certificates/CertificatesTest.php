<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Certificates;
use Froxlor\Api\Commands\SubDomains;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\Certificates
 */
class CertificatesTest extends TestCase
{

	public function testAdminCertificatesAdd()
	{
		global $admin_userdata;

		$json_result = SubDomains::getLocal($admin_userdata, array(
			'domainname' => 'test2.local'
		))->get();
		$domain = json_decode($json_result, true)['data'];
		$domainid = $domain['id'];

		$certdata = $this->generateKey();
		$json_result = Certificates::getLocal($admin_userdata, array(
			'domainname' => 'test2.local',
			'ssl_cert_file' => $certdata['cert'],
			'ssl_key_file' => $certdata['key']
		))->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($domainid, $result['domainid']);
	}

	public function testResellerCertificatesAddAgain()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		$certdata = $this->generateKey();
		$this->expectExceptionCode(406);
		$this->expectExceptionMessage("Domain 'test2.local' already has a certificate. Did you mean to call update?");
		$json_result = Certificates::getLocal($reseller_userdata, array(
			'domainname' => 'test2.local',
			'ssl_cert_file' => $certdata['cert'],
			'ssl_key_file' => $certdata['key']
		))->add();
	}

	public function testCustomerCertificatesAdd()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$json_result = SubDomains::getLocal($admin_userdata, array(
			'domainname' => 'mysub2.test2.local'
		))->get();
		$domain = json_decode($json_result, true)['data'];
		$domainid = $domain['id'];

		$certdata = $this->generateKey();
		$json_result = Certificates::getLocal($customer_userdata, array(
			'domainname' => 'mysub2.test2.local',
			'ssl_cert_file' => $certdata['cert'],
			'ssl_key_file' => $certdata['key']
		))->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($domainid, $result['domainid']);
	}

	/**
	 * regression test for GHSA-89vj-gqqr-73p8: the certificate's issuer organization
	 * name is attacker-controlled (a customer can upload/self-sign any certificate for
	 * their own domain) and was stored verbatim, allowing a stored-XSS payload to reach
	 * the admin panel wherever the issuer is displayed. It must be sanitized to a safe
	 * character set before being stored.
	 */
	public function testCustomerCertificatesAddSanitizesIssuerOrganization()
	{
		global $admin_userdata;

		$customer_userdata = json_decode(Customers::getLocal($admin_userdata, [
			'loginname' => 'test1'
		])->get(), true)['data'];

		// dedicated subdomain so this test doesn't depend on fixtures from other test
		// files/classes (e.g. mysub.test2.local is created and later deleted again
		// within SubDomainsTest.php itself)
		SubDomains::getLocal($admin_userdata, [
			'subdomain' => 'issuertest',
			'domain' => 'test2.local',
			'customerid' => $customer_userdata['customerid']
		])->add();
		$json_result = SubDomains::getLocal($admin_userdata, array(
			'domainname' => 'issuertest.test2.local'
		))->get();
		$domain = json_decode($json_result, true)['data'];
		$domainid = $domain['id'];

		$certdata = $this->generateKey('<script>alert(document.cookie)</script>;rm -rf /');
		$json_result = Certificates::getLocal($admin_userdata, array(
			'domainname' => 'issuertest.test2.local',
			'ssl_cert_file' => $certdata['cert'],
			'ssl_key_file' => $certdata['key']
		))->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($domainid, $result['domainid']);
		$this->assertStringNotContainsString('<', $result['issuer']);
		$this->assertStringNotContainsString('>', $result['issuer']);
		$this->assertStringNotContainsString(';', $result['issuer']);

		// cleanup: cert is deleted along with the domain
		SubDomains::getLocal($admin_userdata, array(
			'domainname' => 'issuertest.test2.local',
			'customerid' => $customer_userdata['customerid']
		))->delete();
	}

	public function testAdminCertificatesList()
	{
		global $admin_userdata;

		$json_result = Certificates::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result['count']);

		$json_result = Certificates::getLocal($admin_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result);
	}

	public function testResellerCertificatesList()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		$json_result = Certificates::getLocal($reseller_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result['count']);

		$json_result = Certificates::getLocal($reseller_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result);
	}

	public function testCustomerCertificatesList()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$json_result = Certificates::getLocal($customer_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result['count']);

		$json_result = Certificates::getLocal($customer_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result);
	}

	public function testAdminCertificatesUpdate()
	{
		global $admin_userdata;

		$certdata = $this->generateKey();
		$json_result = Certificates::getLocal($admin_userdata, array(
			'domainname' => 'test2.local',
			'ssl_cert_file' => $certdata['cert'],
			'ssl_key_file' => $certdata['key']
		))->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(str_replace("\n", "", $certdata['cert']), str_replace("\n", "", $result['ssl_cert_file']));
	}

	public function testCustomerCertificatesUpdate()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$certdata = $this->generateKey();
		$json_result = Certificates::getLocal($customer_userdata, array(
			'domainname' => 'mysub2.test2.local',
			'ssl_cert_file' => $certdata['cert'],
			'ssl_key_file' => $certdata['key']
		))->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(str_replace("\n", "", $certdata['cert']), str_replace("\n", "", $result['ssl_cert_file']));
	}

	/**
	 *
	 * @depends testAdminCertificatesUpdate
	 */
	public function testCustomerCertificatesDelete()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$json_result = Certificates::getLocal($customer_userdata, array(
			'id' => 1
		))->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(isset($result['domainid']) && $result['domainid'] > 0);
	}

	private function generateKey($organizationName = "Froxlor")
	{
		$dn = array(
			"countryName" => "DE",
			"stateOrProvinceName" => "Hessen",
			"localityName" => "Frankfurt",
			"organizationName" => $organizationName,
			"organizationalUnitName" => "Testing",
			"commonName" => "test2.local",
			"emailAddress" => "team@froxlor.org"
		);

		// generate key pair
		$privkey = openssl_pkey_new(array(
			"private_key_bits" => 2048,
			"private_key_type" => OPENSSL_KEYTYPE_RSA
		));

		// generate csr
		$csr = openssl_csr_new($dn, $privkey, array(
			'digest_alg' => 'sha256'
		));

		// generate self-signed certificate
		$sscert = openssl_csr_sign($csr, null, $privkey, 365, array(
			'digest_alg' => 'sha256'
		));

		// export
		openssl_x509_export($sscert, $certout);
		openssl_pkey_export($privkey, $pkeyout, null);

		return array(
			'cert' => $certout,
			'key' => $pkeyout
		);
	}
}
