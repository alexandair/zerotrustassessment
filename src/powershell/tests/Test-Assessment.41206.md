Workbooks are Sentinel's primary visualization surface for SOC operations: they aggregate KQL queries against the workspace into curated dashboards (Microsoft Entra audit, Azure Activity, Office 365, Microsoft Defender XDR, data-collection health, identity-and-access, threat intelligence, security operations efficiency) so analysts can perform trend analysis, hunt visually, monitor connector health, and brief leadership with consistent metrics. Without workbooks, the SOC has no executive view, no longitudinal trend dashboards, and no visual entry point into the workspace; analysts revert to ad-hoc KQL, which slows investigation and increases the chance that a slow-burn pattern indicating a threat actor in the persistence or collection phase is missed. Workbooks are also the documented vehicle for Microsoft-published health-monitoring dashboards (Data Collection Health, Microsoft Sentinel Cost, Workspace Audit) that surface degradations in detection capability before they become detection gaps. The check confirms at least one workbook is deployed; production deployments typically install the recommended workbook set per the customer's connector inventory.

**Remediation action**

- [Visualize collected data with Microsoft Sentinel workbooks](https://learn.microsoft.com/azure/sentinel/monitor-your-data)
- [Deploy Microsoft Sentinel content from the content hub](https://learn.microsoft.com/azure/sentinel/sentinel-solutions-deploy)

<!--- Results --->
%TestResult%
