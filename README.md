This repository will contain STIG remediation scripts that I've created.
Everytime I add a new script I will add an entry here with a bit of an explanation/description.

11/05/2024 - 11/09/2024
added 'before_report.html' --> a report detailing a oscap scan done on a rocky 9 container.
added 'after_report.html' --> a re-scan of the container containing the results of my mitigation scripts. 
			  -- some hits still show as failed even though the required settings are inside the specified file.
added 'stig_remediation.sh --> a bash script that fixes the stig hits reported by 'before_report.html'.


NOTES: 

on https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/ you can use the STIGREF 'Rule ID' number from the oscap report to lookup the corresponding
STIG ID on the stigviewer website. To accomplish this just grab the 'V-' and following six digits to look up on the stigviewer website. 

for example: SV-258096r926275_rule will match V-258096 in stigviewer.com's RHEL 9 OS STIG listings. 
