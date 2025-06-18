# 🛡️ Secure Dependency Scanner

A comprehensive security scanner for detecting suspicious dependencies, malicious packages, and vulnerabilities in Node.js projects. Protects against supply-chain attacks, typosquatting, and other NPM-based threats.

## 🔐 How to Verify This Package is Legitimate

**⚠️ IMPORTANT: Before installing any security tool, verify it's legitimate!**

### 1. **Check the Source**
- **GitHub Repository**: https://github.com/fsegall/secure-dep-scanner
- **Author**: Felipe Segall Corrêa (Livre Software Solutions)
- **Company**: https://livresoltech.com
- **NPM Package**: https://www.npmjs.com/package/secure-dep-scanner

### 2. **Verify Package Integrity**
```bash
# Check package checksum
npm view secure-dep-scanner dist.integrity

# Verify against GitHub release
git clone https://github.com/livresoltech/secure-dep-scanner.git
cd secure-dep-scanner
npm pack
# Compare the generated .tgz with the published package
```

### 3. **Review the Code**
- **Zero Dependencies**: This package has no external dependencies to prevent supply-chain attacks
- **Open Source**: All detection logic is transparent and reviewable
- **Self-Contained**: Single file (`security-scanner.cjs`) with no external calls
- **No Network Access**: The scanner doesn't make network requests during operation

### 4. **Check for Red Flags**
- ✅ **No suspicious network calls**
- ✅ **No credential collection**
- ✅ **No data exfiltration**
- ✅ **No obfuscated code**
- ✅ **Transparent detection patterns**
- ✅ **Reputable author and company**

### 5. **Alternative Verification**
```bash
# Use npx to run without installation
npx secure-dep-scanner --help

# Use built-in verification command
npx secure-dep-scanner --verify

# Review the source code first
curl -s https://raw.githubusercontent.com/livresoltech/secure-dep-scanner/main/security-scanner.cjs | head -50
```

**🔒 Security Note**: This package is designed to be transparent and safe. If you find anything suspicious, please report it immediately.

---

## 🚀 Features

### 🔍 **Dependency Analysis**
- Scans `package.json` for suspicious dependencies
- Detects typosquatting attacks (malicious package name variations)
- Identifies deprecated and vulnerable packages
- Flags known malicious packages

### 🕵️ **Content Scanning**
- Analyzes `node_modules` for malicious code patterns
- Detects suspicious IP addresses and command execution
- Scans for known malware signatures
- Identifies suspicious file content

### 🛡️ **Vulnerability Detection**
- Integrates with `npm audit` for comprehensive vulnerability scanning
- Categorizes issues by severity (Critical, High, Medium, Low)
- Provides actionable recommendations

### 🎯 **Smart Detection**
- Whitelist of legitimate packages to reduce false positives
- Pattern-based detection for emerging threats
- Age-based detection for potential typosquatting

### 🎨 **Enhanced CLI Experience**
- **Color-coded output** for better readability
- **Progress indicators** for long-running scans
- **Interactive confirmations** for critical actions
- **Multiple output formats** (Console, JSON, CSV, HTML)
- **Configuration file support** for custom rules
- **Quiet mode** for automation and CI/CD
- **Non-interactive mode** for scripting

## 📦 Installation

```bash
npm install -g secure-dep-scanner
```

Or use it directly without installation:

```bash
npx secure-dep-scanner
```

## 🚀 Quick Start

Navigate to your Node.js project directory and run:

```bash
secure-dep-scanner
```

The scanner will automatically:
1. Scan your `package.json` dependencies
2. Analyze `node_modules` content
3. Run `npm audit`
4. Generate a comprehensive security report

## 📋 Usage Examples

### Basic Scan
```bash
# Scan current directory
secure-dep-scanner

# Or use npx
npx secure-dep-scanner

# Verify package legitimacy first
npx secure-dep-scanner --verify
```

### Advanced Usage
```bash
# Output as JSON for automation
secure-dep-scanner --format json

# Save report to file
secure-dep-scanner --output security-report.json

# Generate HTML report
secure-dep-scanner --format html --output report.html

# Generate CSV for analysis
secure-dep-scanner --format csv --output issues.csv

# Quiet mode (suppress output)
secure-dep-scanner --quiet

# Non-interactive mode (no prompts)
secure-dep-scanner --no-interactive

# Combine options
secure-dep-scanner --format json --output report.json --quiet
```

### Programmatic Usage
```javascript
const SecurityScanner = require('secure-dep-scanner');

const scanner = new SecurityScanner({
  interactive: false,
  outputFormat: 'json',
  quiet: true
});

scanner.scan().then(issues => {
  console.log('Found issues:', issues.length);
});
```

## 📊 Sample Output

```
🛡️ Starting Security Scan...

🔍 Scanning package.json for suspicious dependencies...
🔍 Scanning node_modules for malicious content...
🔍 Running npm audit...

🛡️ SECURITY SCAN REPORT
==================================================
🚨 CRITICAL: 0
🔴 HIGH: 2
🟡 MEDIUM: 1
🟢 LOW: 3
📊 TOTAL: 6

📋 DETAILED ISSUES:
--------------------------------------------------
1. ⚠️ HIGH: Found suspicious pattern "crypto" in package.json
   Package: crypto@1.0.1
2. 🔴 HIGH: crypto@1.0.1 - Deprecated package with vulnerabilities
   Package: crypto@1.0.1

💡 RECOMMENDATIONS:
--------------------------------------------------
⚠️ REVIEW RECOMMENDED:
   - Review suspicious packages
   - Update vulnerable dependencies

⏱️ Scan completed in 1247ms
```

## 🎯 What It Detects

### 🚨 **Critical Issues**
- Known malicious IP addresses
- Confirmed malware signatures
- Critical security vulnerabilities

### ⚠️ **High Priority**
- Suspicious package patterns
- Deprecated packages with vulnerabilities
- Known malicious packages

### 🔍 **Medium Priority**
- Command execution patterns in suspicious contexts
- New packages (potential typosquatting)
- Suspicious content patterns

### 📝 **Low Priority**
- General security recommendations
- Audit warnings
- Monitoring suggestions

## 🛡️ Protection Features

### **Zero Dependencies**
- No external packages to avoid supply-chain attacks
- Self-contained security scanner
- Transparent detection logic

### **Smart Whitelisting**
- Recognizes legitimate packages
- Reduces false positives
- Focuses on suspicious content

### **Real-time Detection**
- Pattern-based threat detection
- Updated with latest threat intelligence
- Adaptable to new attack vectors

## 🔧 Configuration

The scanner works out-of-the-box but you can customize detection patterns by modifying the source code:

```javascript
// Add custom suspicious patterns
this.suspiciousPatterns.push('your-suspicious-pattern');

// Add blocked packages
this.blockedPackages.add('malicious-package-name');

// Add suspicious IPs
this.suspiciousIPs.add('192.168.1.100');
```

### Configuration Files
The scanner automatically loads configuration from these files (in order):
- `.secure-dep-scanner.json`
- `.secure-dep-scanner.yaml`
- `.secure-dep-scanner.yml`
- `secure-dep-scanner.json`

Example configuration:
```json
{
  "suspiciousPatterns": ["custom-pattern"],
  "blockedPackages": ["malicious-package"],
  "suspiciousIPs": ["192.168.1.100"],
  "interactive": false,
  "quiet": true
}
```

## 🚨 Exit Codes

- **0**: No critical issues found
- **1**: Critical security issues detected

## 📈 Performance

- **Fast**: Typically completes in 1-3 seconds
- **Lightweight**: No external dependencies
- **Efficient**: Smart filtering reduces scan time

## 🔗 Integration & Automation

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Security Scan
  run: npx secure-dep-scanner --format json --output security-report.json

- name: Check for Critical Issues
  run: |
    if jq '.critical > 0' security-report.json; then
      echo "Critical security issues found!"
      exit 1
    fi
```

### Pre-commit Hooks
```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "secure-dep-scanner --quiet"
    }
  }
}
```

### Scheduled Scans
```bash
# Add to crontab for daily scans
0 9 * * * cd /path/to/project && secure-dep-scanner --format json --output daily-scan.json
```

### API Integration
```javascript
const SecurityScanner = require('secure-dep-scanner');

// Custom integration
async function securityCheck() {
  const scanner = new SecurityScanner({
    interactive: false,
    quiet: true
  });
  
  const issues = await scanner.scan();
  
  // Send to security dashboard
  await sendToDashboard(issues);
  
  return issues;
}
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/livresoltech/secure-dep-scanner.git
cd secure-dep-scanner
npm test
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- **GitHub**: https://github.com/livresoltech/secure-dep-scanner
- **Issues**: https://github.com/livresoltech/secure-dep-scanner/issues
- **Security**: See [SECURITY.md](SECURITY.md) for security policy

## ⚠️ Disclaimer

This tool is provided as-is for educational and security purposes. While we strive for accuracy, no security tool is perfect. Always:

- Use multiple security tools
- Keep dependencies updated
- Follow security best practices
- Verify suspicious findings manually

## 🎉 Support

If you find this tool helpful, consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting improvements
- 🔒 Contributing to security

---

**Made with ❤️ by [Livre Software Solutions](https://livresoltech.com)**

## ⚠️ Why Are Popular Packages Like Lodash Flagged?

**This scanner flags any code patterns that are commonly abused in malware, such as use of `Function`, `setTimeout`, `exec`, or suspicious keywords—even in popular packages like Lodash.**

- **This does NOT mean these packages are malicious!**
- These patterns are flagged so you can review them and make an informed decision.
- You can whitelist legitimate packages to reduce noise (see configuration section).

**The goal is to surface anything potentially risky, not to automatically label packages as unsafe.**

## 🎭 Real-World Attack Scenarios

### Fake Job Position Offering
**Attack Vector:** Malicious actors post fake job positions on LinkedIn, offering candidates a "coding challenge" or "project to complete."

**How It Works:**
1. Attacker creates a fake company profile on LinkedIn
2. Posts a job opening for a developer position
3. Sends candidates a "test project" with malicious dependencies
4. When candidates run `npm install`, malicious packages execute
5. Attacker gains access to the candidate's system and potentially their network

**Example Scenario:**
```
"Hi! We loved your profile. For the next round, please complete this coding challenge:
https://github.com/fake-company/test-project

Just clone, run 'npm install', and submit your solution!"
```

**How secure-dep-scanner Protects You:**
- Scans the project's dependencies before installation
- Detects suspicious packages and patterns
- Warns about potentially malicious code
- Prevents execution of harmful packages

**Red Flags to Watch For:**
- Job offers that seem too good to be true
- Requests to install and run unknown projects
- Projects with suspicious package names
- Dependencies that don't match the project's purpose

--- 