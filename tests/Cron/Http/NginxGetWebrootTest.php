<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Cron\Http\Nginx;
use Froxlor\Cron\Http\WebserverBase;

/**
 * regression test: getVhostContent() used to call getWebroot() unconditionally whenever
 * documentroot looked like a redirect-target URL (e.g. the ssl-redirect case, where
 * documentroot is temporarily set to "https://$host/"), even though the return value is
 * only used for the deactivated-docroot fallback further down. getWebroot()'s write-time
 * documentroot revalidation then tried to validate that URL as a filesystem path, failed,
 * and logged a spurious error for every ssl-redirect vhost render. getWebroot() must only
 * be called when its result will actually be used, i.e. when the domain/customer is
 * actually deactivated and a deactivated-docroot is configured.
 *
 * @covers \Froxlor\Cron\Http\Nginx
 * @covers \Froxlor\Cron\Http\WebserverBase
 */
class NginxGetWebrootTest extends TestCase
{
	public function testGetWebrootNotCalledForActiveSslRedirectDomain()
	{
		global $admin_userdata;

		$json_result = Customers::getLocal($admin_userdata, [
			'loginname' => 'test1'
		])->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domain' => 'nginxvhostredirecttest.local',
			'customerid' => $customer_userdata['customerid'],
			'override_tls' => 1,
			'ssl_protocols' => ['TLSv1.2', 'TLSv1.3']
		];
		Domains::getLocal($admin_userdata, $data)->add();

		$json_result = Domains::getLocal($admin_userdata, [
			'domainname' => 'nginxvhostredirecttest.local',
			'ssl_redirect' => 1
		])->update();
		$domain_data = json_decode($json_result, true)['data'];
		$this->assertEquals('1', (string)$domain_data['ssl_redirect']);

		// 'ssl' isn't a real column - WebserverBase::getVhostsToCreate() derives it per-domain
		// from whether an ssl-enabled ip/port is assigned, which is exactly what triggers the
		// ssl-redirect documentroot substitution in getVhostContent()
		$domains = WebserverBase::getVhostsToCreate();
		$this->assertArrayHasKey('nginxvhostredirecttest.local', $domains);
		$domain = $domains['nginxvhostredirecttest.local'];
		$this->assertEquals('1', (string)$domain['ssl']);
		$this->assertEquals('0', (string)$domain['deactivated']);
		$this->assertEquals('0', (string)$domain['customer_deactivated']);

		// getLogFiles() touches real logfile paths on disk, irrelevant to this regression
		// test and not something the test filesystem provides - stub it out
		$nginx = $this->getMockBuilder(Nginx::class)
			->onlyMethods(['getWebroot', 'getLogFiles'])
			->getMock();
		$nginx->expects($this->never())->method('getWebroot');
		$nginx->method('getLogFiles')->willReturn('');

		$method = new ReflectionMethod(Nginx::class, 'getVhostContent');
		$method->setAccessible(true);
		$vhost_content = $method->invoke($nginx, $domain, false);

		// the redirect-to-https content must still be generated correctly
		$this->assertStringContainsString('return 301 https://$host$request_uri;', $vhost_content);

		Domains::getLocal($admin_userdata, [
			'domainname' => 'nginxvhostredirecttest.local'
		])->delete();
	}
}
