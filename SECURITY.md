# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 1. **DO NOT** create a public GitHub issue
Security vulnerabilities should be reported privately to avoid potential exploitation.

### 2. Contact Information
- **Email**: contato@livresoltech.com
- **Subject**: `[SECURITY] Vulnerability Report - secure-dep-scanner`
- **Response Time**: We aim to respond within 24-48 hours

### 3. Include in Your Report
- **Description**: Clear description of the vulnerability
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Impact**: Potential impact and severity assessment
- **Environment**: OS, Node.js version, and any relevant details
- **Proof of Concept**: If applicable, include a safe PoC

### 4. What Happens Next
1. **Acknowledgment**: You'll receive an acknowledgment within 48 hours
2. **Investigation**: Our security team will investigate the report
3. **Updates**: We'll keep you informed of our progress
4. **Fix**: We'll develop and test a fix
5. **Disclosure**: We'll coordinate disclosure with you

## Security Best Practices

### For Users
- **Keep Updated**: Always use the latest version
- **Regular Scans**: Run security scans regularly
- **Verify Sources**: Only install packages from trusted sources
- **Monitor Dependencies**: Keep dependencies updated
- **Use Multiple Tools**: Don't rely on a single security tool

### For Contributors
- **Code Review**: All code changes require security review
- **Dependencies**: Minimize external dependencies
- **Testing**: Include security tests in pull requests
- **Documentation**: Document security-related changes

## Security Features

### Built-in Protections
- **Zero Dependencies**: No external packages to avoid supply chain attacks
- **Static Analysis**: No code execution during scanning
- **Transparent Logic**: All detection logic is open source
- **Regular Updates**: Updated with latest threat intelligence

### Detection Capabilities
- **Typosquatting**: Detects malicious package name variations
- **Suspicious Metadata**: Identifies unusual package information
- **Known Malware**: Flags known malicious packages
- **Vulnerabilities**: Integrates with npm audit
- **Deprecated Packages**: Identifies outdated dependencies

## Disclosure Policy

### Timeline
- **Critical**: 24-48 hours
- **High**: 1-2 weeks
- **Medium**: 2-4 weeks
- **Low**: 1-2 months

### Process
1. **Private Fix**: Develop and test fix privately
2. **Coordination**: Coordinate with reporter
3. **Release**: Release fix with security advisory
4. **Documentation**: Update security documentation

## Security Contacts

### Primary Contact
- **Name**: Felipe Segall Corrêa
- **Email**: contato@livresoltech.com
- **Company**: Livre Software Solutions
- **Website**: https://livresoltech.com

### Backup Contact
- **GitHub Security**: Use GitHub's security advisory feature
- **Response Time**: 24-48 hours

## Bug Bounty

Currently, we do not offer a formal bug bounty program. However, we greatly appreciate security researchers who responsibly disclose vulnerabilities and may offer recognition in our security hall of fame.

## Security Hall of Fame

We recognize security researchers who help improve our security:

- **2024**: [To be added as vulnerabilities are reported]

## Updates

This security policy is regularly reviewed and updated. Last updated: June 2024.

---

**Remember**: Security is everyone's responsibility. If you see something, say something!
