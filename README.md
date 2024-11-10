This repository will contain STIG remediation scripts that I've created.
Every time I add a new script I will add an entry here with a bit of an explanation/description.

11/05/2024 - 11/09/2024

added 'before_report.html' --> a report detailing an OpenScap scan done on a rocky 9 container.

added 'after_report.html' --> a re-scan of the container containing the results of my mitigation scripts.
			      some hits still show as failed even though the required settings are inside the specified file.
	 
added 'stig_remediation.sh --> a bash script that fixes the stig hits reported by 'before_report.html'.


NOTES: 

on https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/ you can use the STIGREF 'Rule ID' number from the OpenScap report to look up the corresponding
STIG ID on the Stigviewer website. To accomplish this just grab the 'V-' and the following six digits to look up on the Stigviewer website. 

for example: SV-258096r926275_rule will match V-258096 in stigviewer.com's RHEL 9 OS STIG listings. 
