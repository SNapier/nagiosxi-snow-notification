# nagiosxi-snow-notification

Python script to allow for NagiosXI to create and resolve monitoing realted incidents within ServiceNow utilizing the API/Incidents Table

## NagiosXI Configuration
### Credentials
### Upload files to NagosXI
### NagiosXI Host Command Definition
### NagiosXI Service Command Definition

#### Command Input Vairables
1. REQUIRED
..* senv SENV ..
..* nenv NENV ..
..* type TYPE ..
..* etype ETYPE ..
..* hostname HOSTNAME ..
..* hostaddress HOSTADDRESS ..
..* changegroup CHANGEGROUP ..
..* downtime DOWNTIME ..

2. OPTIONAL BASED ON TYPE
..* [--lastservicestateid LASTSERVICESTATEID] ..
..* [--servicestateid SERVICESTATEID] ..
..* [--serviceeventid SERVICEEVENTID] ..
..* [--serviceproblemid SERVICEPROBLEMID] ..
..* [--lastserviceeventid LASTSERVICEEVENTID] ..
..* [--lastserviceproblemid LASTSERVICEPROBLEMID] ..
..* [--lasthoststateid LASTHOSTSTATEID] ..
..* [--hoststateid HOSTSTATEID] ..
..* [--hosteventid HOSTEVENTID] ..
..* [--hostproblemid HOSTPROBLEMID] ..
..* [--lasthosteventid LASTHOSTEVENTID] ..
..* [--lasthostproblemid LASTHOSTPROBLEMID] ..
..* [--timeinstate TIMEINSTATE] ..
..* [--lasttimeok LASTTIMEOK] ..
..* [--lasttimecritical LASTTIMECRITICAL] .. 
..* [--servicestatetype SERVICESTATETYPE] ..
..* [--summary SUMMARY] ..
..* [--impact IMPACT] ..
..* [--urgency URGENCY] ..
..* [--source SOURCE] ..
..* [--notes NOTES] ..
..* [--debug -d] ..

#### Using NagiosXI Custom Vars
- Impact
- Urgency
- ChangeGroup

### Logging & Debugging

### Using NagiosXI Notificaiton Commands
..* NagiosXI