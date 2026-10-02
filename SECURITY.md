# froxlor's Security Policy

Welcome and thanks for taking interest in [froxlor](https://www.froxlor.org)!

We are mostly interested in reports by actual froxlor users but all high quality contributions are welcome.

Please try your best to describe a clear and realistic impact for your report and please don't open any public issues on GitHub or social media, we're doing our best to respond through huntr as quickly as we can.

With that, good luck hacking us ;)

## Supported versions

- ️✅ **2.3.x**  (`main` and `v2.3` git-branch)
- ️❌ <=2.2.x
- ❌ other git-branches

## Qualifying Vulnerabilities

### Vulnerabilities we really care about
- SQL injection bugs
- server-side code execution bugs
- cross-site scripting vulnerabilities
- cross-site request forgery vulnerabilities
- authentication and authorization flaws
- sensitive information disclosure

### Vulnerabilities we accept

Only reproducible issues on a default/clean setup from the latest stable release of a supported version will be accepted.

## Non-Qualifying Vulnerabilities

- Reports from automated tools or scanners
- Theoretical attacks without proof of exploitability
- Attacks that are the result of a third party library should be reported to the library maintainers
- Social engineering
- Attacks that require disabling security features or reducing the security level of the environment
- Exploits by an admin user itself (privileged user and implicitly trusted)
- Reflected file download
- Physical attacks
- Weak SSL/TLS/SSH algorithms or protocols
- Attacks involving physical access to a user’s device, or involving a device or network that’s already seriously compromised (eg man-in-the-middle).
- The user attacks themselves
- anything in `/doc`
- anything in `/tests`

## Reporting a Vulnerability

If you think you have found a vulnerability in froxlor, please head over to [https://github.com/Froxlor/Froxlor/security/advisories](https://github.com/Froxlor/Froxlor/security/advisories/new) and use the reporting possibilities there. Also, please give us appropriate time to fix the issue and build update-packages before publishing anything into the wild. Alternatively you can email us to [team@froxlor.org](team@froxlor.org).
