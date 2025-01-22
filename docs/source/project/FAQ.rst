Frequently Asked Questions
=======
1. If I enable mailbox auditing now can I see historical records?
    - No, additionaly if you enable auditing now it can take up to 24 hours before events will be logged.

2. Which date format does the script accepts as input?
    - The date format used by the tool will depend on the current date settings of the system where the script is being run.

3. Do I need to configure the time period?
    - When you omit a timestamp in the StartDate or EndDate parameter values, the default timestamp of 12:00 AM (midnight) is used by the script.

4. What about timestamps?
    - The audit logs are recorded in UTC and will be exported in the same time zone.

5. What is the retention period?
    - Audit (Standard) - Logs generated before October 17, 2024 are retained for 90 days. Audit (Standard) logs generated on or after October 17, 2024 follow the new default retention of 180 days.
    - OAudit (Premium) - Audit records are retained for 365 days (one year). That means you can search the audit log for activities that were performed within the last year. To retain audit logs for 10 years, the user who generates the audit log must also be assigned a 10-year audit log retention add-on license in addition to an E5 license.

6. What if I have E5 or other license that has more than 90 days?
    - Just define a manual startdate instead of the 'maximum' because the variable maximum is set to 90 days, which is the default for almost everyone.
