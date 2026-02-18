Azure Application Gateway is a regional web traffic load balancer that enables you to manage traffic to your web applications. Web Application Firewall (WAF) on Application Gateway provides centralized protection for web applications against common exploits and vulnerabilities such as SQL injection, cross-site scripting, and other OWASP Top 10 threats.

Request body inspection is a critical WAF capability that analyzes the content of HTTP POST, PUT, and PATCH request bodies for malicious patterns. When request body inspection is disabled, the WAF can only evaluate HTTP headers and URL parameters, leaving a significant attack surface unmonitored. Threat actors commonly embed malicious payloads in request bodies through form submissions, API calls, and file uploads to evade detection.

Without request body inspection enabled, attackers can:
- Execute SQL injection attacks by embedding malicious SQL statements in form data
- Perform cross-site scripting (XSS) by injecting scripts into POST request bodies
- Upload malicious files or exploit file upload vulnerabilities
- Execute command injection through API payloads
- Bypass all WAF managed rule sets that rely on body content analysis

This check verifies that all Application Gateway WAF policies attached to Application Gateways have request body inspection enabled (`requestBodyCheck: true`). Only WAF policies actively protecting Application Gateways are evaluated; unattached policies are excluded from the assessment.

**Remediation action**

- [What is Azure Web Application Firewall on Azure Application Gateway?](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview)
- [Create Web Application Firewall policies for Application Gateway](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/create-waf-policy-ag)
- [Tuning Web Application Firewall for Azure Application Gateway](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-faq)

<!--- Results --->
%TestResult%
