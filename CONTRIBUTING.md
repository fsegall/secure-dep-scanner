# Contributing to Secure Dependency Scanner

Thank you for your interest in contributing to our security scanner! We welcome contributions from the community to help make NPM packages safer for everyone.

## 🤝 How to Contribute

### 🐛 Reporting Bugs
- Use the [GitHub Issues](https://github.com/livresoltech/secure-dep-scanner/issues) page
- Include detailed steps to reproduce the issue
- Provide your Node.js version and OS information
- Include any error messages or logs

### 💡 Suggesting Enhancements
- Open a feature request on GitHub Issues
- Describe the enhancement and its benefits
- Consider security implications
- Provide use cases if applicable

### 🔧 Code Contributions
- Fork the repository
- Create a feature branch (`git checkout -b feature/amazing-feature`)
- Make your changes
- Add tests if applicable
- Commit your changes (`git commit -m 'Add amazing feature'`)
- Push to the branch (`git push origin feature/amazing-feature`)
- Open a Pull Request

## 🛡️ Security Guidelines

### Code Review Process
- All code changes require security review
- Security-related changes need additional scrutiny
- We may request security testing for new features

### Security Best Practices
- Follow secure coding practices
- Avoid introducing new dependencies unless absolutely necessary
- Document security implications of changes
- Test thoroughly before submitting

## 🧪 Testing

### Running Tests
```bash
npm test
```

### Adding Tests
- Add tests for new features
- Ensure existing tests still pass
- Test edge cases and security scenarios
- Include both positive and negative test cases

## 📝 Code Style

### JavaScript Guidelines
- Use ES6+ features where appropriate
- Follow consistent naming conventions
- Add JSDoc comments for functions
- Keep functions focused and small

### File Structure
- Keep related functionality together
- Use descriptive file and function names
- Maintain clear separation of concerns

## 🔍 Detection Patterns

### Adding New Patterns
When adding new detection patterns:

1. **Research thoroughly** - Verify the pattern is actually malicious
2. **Test extensively** - Ensure it doesn't cause false positives
3. **Document clearly** - Explain why the pattern is suspicious
4. **Update whitelist** - Add legitimate packages that might trigger it

### Pattern Categories
- **Typosquatting**: Malicious package name variations
- **Malware signatures**: Known malicious code patterns
- **Suspicious behavior**: Unusual package characteristics
- **Vulnerabilities**: Security weaknesses in packages

## 📚 Documentation

### Updating Documentation
- Keep README.md current with new features
- Update usage examples when APIs change
- Document new configuration options
- Maintain accurate security information

### Documentation Standards
- Use clear, concise language
- Include practical examples
- Explain security implications
- Keep formatting consistent

## 🚀 Release Process

### Version Bumping
- Follow semantic versioning (MAJOR.MINOR.PATCH)
- Update package.json version
- Update CHANGELOG.md with changes
- Tag releases appropriately

### Pre-release Checklist
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Security review completed
- [ ] Performance impact assessed
- [ ] Backward compatibility verified

## 🎯 Areas for Contribution

### High Priority
- **Detection accuracy**: Improve pattern matching
- **Performance**: Optimize scanning speed
- **Coverage**: Add more threat detection patterns
- **Documentation**: Improve user guides

### Medium Priority
- **Integration**: Add support for other package managers
- **Reporting**: Enhance output formats
- **Configuration**: Add more customization options
- **Testing**: Expand test coverage

### Low Priority
- **UI improvements**: Better console output
- **Logging**: Enhanced debugging information
- **Examples**: More usage examples
- **Tutorials**: Step-by-step guides

## 🤝 Community Guidelines

### Be Respectful
- Treat all contributors with respect
- Provide constructive feedback
- Be patient with newcomers
- Help others learn and grow

### Be Collaborative
- Share knowledge and expertise
- Help review others' contributions
- Suggest improvements constructively
- Celebrate community achievements

## 📞 Getting Help

### Questions and Support
- Check existing issues and documentation
- Ask questions in GitHub Discussions
- Reach out to maintainers for guidance
- Join our community channels

### Mentorship
- We're happy to mentor new contributors
- Ask for help with your first contribution
- We can pair program on complex features
- We provide guidance on security concepts

## 🏆 Recognition

### Contributors
- All contributors are listed in our README
- Significant contributions get special recognition
- We highlight security researchers who help
- Contributors are mentioned in release notes

### Hall of Fame
- Exceptional contributions are celebrated
- Security researchers are honored
- Long-term contributors are recognized
- Community leaders are highlighted

---

**Thank you for helping make the NPM ecosystem safer!** 🛡️

Your contributions help protect developers and organizations from supply-chain attacks and malicious packages. 