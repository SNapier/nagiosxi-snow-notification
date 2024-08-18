# nagiosxi-snow-notification

Python script to allow for NagiosXI to create and resolve monitoing realted incidents within ServiceNow utilizing the API/Incidents Table

## NagiosXI Configuration
1. Create a Contact Group "ServiceNow"
2. Create a Contact ServiceNow-Dev
  * Both host and Service commands will be applied to the same user.

### Credentials Required
1. ServiceNow
  * ServiceNow Username
  * Base64 encoded Password <-- plain text won't work
  Your user will require permissions to close incidents, please talk with your servicenow team to make sure this is setup Properly within your environment.  

2. NagiosXI
  * User API-Key
  Your user should have permissions to create acknowledgements and comments via the NagiosXI API.

3. Edit the YAML files to to include the credentials for your environment before uploading to the NagiosXI server. 

### Upload files to NagosXI
1. As a user with Admin permissions upload the Python and both edited YAML files via the Admin section in the NagiosXI Interface.

### Create NagiosXI Host Command
1. Name
  * nagiosxi-snow-notification-host
2. Command Line
```bash
python3 $USER1$/nagiosxi-snow-notification.py --senv "dev" --nenv "dev" --type "host" --etype $HOSTNOTIFICATIONTYPE$ -H "$HOSTNAME$" --hostaddress "$HOSTADDRESS$" --changegroup "$_HOSTGHANGEGROUP$" --downtime $HOSTDOWNTIME$ --hoststateid $HOSTSTATEID$ --hostproblemid $HOSTPROBLEMID$ --hosteventid $HOSTEVENTID$ --lasthosteventid $LASTHOSTEVENTID$ --lasthostproblemid $LASTHOSTPROBLEMID$ --timeinstate $HOSTDURATION$ --lasttimeok $LASTHOSTUP$ --lasttimecritical $LASTHOSTDOWN$ --servicestatetype $HOSTSTATETYPE$ --summary "$HOSTOUTPUT$" --impact $_HOSTIMPACT$ --urgency $_HOSTURGENCY$ --source "HOSTCHECK" --notes $HOSTNOTES$
```
3. Command Type
  * misc command

### Create NagiosXI Service Command
1. Name
  * nagiosxi-snow-notification-service
2. Command Line
```bash
python3 $USER1$/nagiosxi-snow-notification.py --senv "dev" --nenv "dev" --type "service" --etype $SERVICENOTIFICATIONTYPE$ -H "$HOSTNAME$" --hostaddress "$HOSTADDRESS$" --changegroup "$_SERVICECHANGEGROUP$" --downtime $SERVICEDOWNTIME$ --servicestateid $SERVICESTATEID$ --serviceproblemid $SERVICEPROBLEMID$ --serviceeventid $SERVICEEVENTID$ --lastserviceeventid $LASTSERVICEEVENTID$ --lastserviceproblemid $LASTSERVICEPROBLEMID$ --timeinstate $SERVICEDURATION$ --lasttimeok $LASTSERVICEOK$ --lasttimecritical $LASTSERVICECRITICAL$ --servicestatetype $SERVICESTATETYPE$ --summary "$SERVICEOUTPUT$" --impact $_SERVICEIMPACT$ --urgency $_SERVICEURGENCY$ --source "$SERVICEDESCRIPTION$" --notes $SERVICENOTES$
```
3. Command Type
  * misc command

### Configure Contact Notification Commands


#### Command Input Vairables
1. REQUIRED
  * senv SENV ..
  * nenv NENV ..
  * type TYPE ..
  * etype ETYPE ..
  * hostname HOSTNAME ..
  * hostaddress HOSTADDRESS ..
  * changegroup CHANGEGROUP ..
  * downtime DOWNTIME ..

2. OPTIONAL BASED ON TYPE
  * [--lastservicestateid LASTSERVICESTATEID] ..
  * [--servicestateid SERVICESTATEID] ..
  * [--serviceeventid SERVICEEVENTID] ..
  * [--serviceproblemid SERVICEPROBLEMID] ..
  * [--lastserviceeventid LASTSERVICEEVENTID] ..
  * [--lastserviceproblemid LASTSERVICEPROBLEMID] ..
  * [--lasthoststateid LASTHOSTSTATEID] ..
  * [--hoststateid HOSTSTATEID] ..
  * [--hosteventid HOSTEVENTID] ..
  * [--hostproblemid HOSTPROBLEMID] ..
  * [--lasthosteventid LASTHOSTEVENTID] ..
  * [--lasthostproblemid LASTHOSTPROBLEMID] ..
  * [--timeinstate TIMEINSTATE] ..
  * [--lasttimeok LASTTIMEOK] ..
  * [--lasttimecritical LASTTIMECRITICAL] .. 
  * [--servicestatetype SERVICESTATETYPE] ..
  * [--summary SUMMARY] ..
  * [--impact IMPACT] ..
  * [--urgency URGENCY] ..
  * [--source SOURCE] ..
  * [--notes NOTES] ..
  * [--debug -d] ..

#### Using NagiosXI Custom Vars
- Impact
- Urgency
- ChangeGroup

### Logging & Debugging

### Using NagiosXI Notificaiton Commands
  * NagiosXI