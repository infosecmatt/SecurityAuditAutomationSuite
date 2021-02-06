# Security Audit Automation Suite
The purpose of this project is to facilitate the auditing process for enterprise networks and systems, whether it be for compliance, governance, or security reasons. It is not comprehensive, but it is meant to streamline the process and automate many of the tasks typically performed manually by auditors and their respective clients without the use of third party tools or software.

The Active Directory audit script was originally based on Clay Risenhoover's script (https://github.com/AuditClay/AuditScripts/blob/master/ADAuditGeneric.ps1) and Trip Hillman, one of my coworkers and an infosec whiz (https://github.com/th3auditor), assisted with the ideation and testing process.

## Todo:
- Create some mechanism for population validation. My initial thought is to run a hash of the script file at the beginning for comparauditorclayison to a hash of the file hosted on github. Likewise, I'd like to zip up the output and run a hash of it for validation of file integrity while testing. To be determined, pending what my bosses say.
- Remove lots of the unnecessary information from the output. Obviously what's necessary is dependent on the type of engagement, but some information in the script output is clearly unnecessary.
- Create a better file structure system for the ouput. Currently, all files are dumped into a single folder which hasn't particularly scaled well in our client environments. Some clients have had upwards of 100 custom groups, which means that combing through the results is cumbersome. I'm thinking about changing the output so that there will be a "group membership" folder, "inactive users" folder, etc.
- Output list of executable files on the machine 
- Indicate whether the script was successfully completed or if there was an error during runtime. could use a try/catch statement or similar.
- Create a questionnaire to accompany the script and gather additional context for the results? For example, inquiring about which groups have access to manage backups, SSO, AV, etc.
