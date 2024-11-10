This repository will contain STIG remediation scripts that I've created.
Everytime I add a new script I will add an entry here with a bit of an explanation/description.

11/05/2024 - 11/09/2024
added 'before_report.html' --> a report detailing a oscap scan done on a rocky 9 container.
added 'after_report.html' --> a re-scan of the container containing the results of my mitigation scripts. 
			  -- some hits still show as failed even though the required settings are inside the specified file.
added 'stig_remediation.sh --> a bash script that fixes the stig hits reported by 'before_report.html'.
