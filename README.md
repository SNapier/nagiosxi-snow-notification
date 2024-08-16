- nagiosxi-snow-notification

-- Python script to allow for NagiosXI to create and resolve monitoing realted incidents within ServiceNow utilizing the API/Incidents Table

Input Vairables
*REQUIRED*
--senv SENV
--nenv NENV
--type TYPE
--etype ETYPE
--hostname HOSTNAME
--hostaddress HOSTADDRESS
--changegroup CHANGEGROUP
--downtime DOWNTIME

*OPTIONAL BASED ON TYPE*
[--lastservicestateid LASTSERVICESTATEID]
[--servicestateid SERVICESTATEID]
[--serviceeventid SERVICEEVENTID]
[--serviceproblemid SERVICEPROBLEMID]
[--lastserviceeventid LASTSERVICEEVENTID]
[--lastserviceproblemid LASTSERVICEPROBLEMID]
[--lasthoststateid LASTHOSTSTATEID]
[--hoststateid HOSTSTATEID]
[--hosteventid HOSTEVENTID]
[--hostproblemid HOSTPROBLEMID]
[--lasthosteventid LASTHOSTEVENTID]
[--lasthostproblemid LASTHOSTPROBLEMID]
[--timeinstate TIMEINSTATE]
[--lasttimeok LASTTIMEOK]
[--lasttimecritical LASTTIMECRITICAL] 
[--servicestatetype SERVICESTATETYPE]
[--summary SUMMARY]
[--impact IMPACT]
[--urgency URGENCY] 
[--source SOURCE] 
[--notes NOTES]   
[--debug -d]