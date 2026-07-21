Microsoft Defender for Endpoint Automated Investigation and Response collects supporting evidence from an alert — process trees, file hashes, registry and persistence changes, network connections, signed-in users — and proposes endpoint remediation actions such as quarantining a malicious file, terminating a running process, removing a persistence entry, or isolating the device. When the device group is configured to require analyst approval and those actions sit in `pendingApproval`, the malicious binary keeps running, the attacker keeps issuing command-and-control traffic, and credentials continue to be harvested for the duration of the delay — the detection landed but the host was never actually contained. This check confirms there are no endpoint AIR actions left in `pendingApproval` past the response window, so a confirmed endpoint detection translates into removal from the host rather than a paused investigation.

## Remediation resources

- [Automated investigation and response in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/m365d-autoir)
- [Review remediation actions in the Action center](https://learn.microsoft.com/en-us/defender-xdr/m365d-autoir-actions)
- [Configure automated investigation and response in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/configure-automated-investigations-remediation)
- [Set automation levels in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/automation-levels)

<!--- Results --->
%TestResult%
