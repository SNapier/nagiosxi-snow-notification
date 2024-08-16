#/usr/bin/python3

import requests, sys, argparse, os, logging, json, yaml, base64, urllib
from urllib.request import HTTPBasicAuthHandler
from time import sleep
from logging.handlers import RotatingFileHandler

#DEAL WITH THE SELF SIGNED NAGIOS SSL
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#NAME
appName = "nagiosxi-snow-notification"
#VERSION
appVersion = "0.0.1"

#PATHS
#DEPENDING ON WHERE YOU WANT TO PUT THE REPORTS
appPath = os.path.dirname(os.path.realpath(__file__))

#PUT THE LOG IN SAME DIR BY DEFAULT
log_dir = appPath+"\\"
#Linux Logging
#log_dir = "/tmp/"

#LOGGING
## CREATE LOGGER
logger = logging.getLogger(appName)
## DEFAULT LOG LEVEL
logger.setLevel(logging.ERROR)

## CREATE CONSOLE LOG HANDLER
ch = logging.StreamHandler()
## CONSOLE HANDLER LOG LEVEL
ch.setLevel(logging.ERROR)

#FILE HANDLER
fh = logging.handlers.RotatingFileHandler(log_dir+appName+".log", mode='a', maxBytes=4096, backupCount=0, encoding=None, delay=False)
##FILE LOG LEVEL
fh.setLevel(logging.ERROR)

##LOG HANDLER FORMATTING
stdFormat = logging.Formatter('[%(asctime)s] level="%(levelname)s"; name="%(name)s"; message="%(message)s";', datefmt='%Y-%m-%dT%H:%M:%S')
debugFormat = logging.Formatter('[%(asctime)s] level="%(levelname)s"; name="%(name)s"; function="%(funappName)s"; line="%(lineno)d"; message="%(message)s";', datefmt='%Y-%m-%dT%H:%M:%S')

##APPLY LOG HANDLER FORMATTING
ch.setFormatter(stdFormat)
fh.setFormatter(stdFormat)

##ADD LOG HANDLERS
logger.addHandler(ch)
logger.addHandler(fh)

##SERVICENOW
def serviceNowConfig(meta):
    with open(appPath+"/nagiosxi-snow-notification.yml", "r") as yamlfile:
        try:
            env = meta.senv
            data = yaml.safe_load(yamlfile)
            r = {"url":data[0]["snow"][env]["url"],"user":data[0]["snow"][env]["uname"],"pass":data[0]["snow"][env]["passwd"]}
        except Exception as e:
            logger.error("%s",e)
            r = False
        finally:
            return r
        
## NAGIOSXI API  
def nagiosxiAPICreds(meta):
    env = meta.nenv
    with open(appPath+"/nagiosxi-snow-notification-xiapi.yml", "r") as yamlfile:
        try:
            data = yaml.safe_load(yamlfile)
            r = {"url":data[0]["nagios"][env]["url"],"apikey":data[0]["nagios"][env]["apikey"]}
        except Exception as e:
            logger.error("%s",e)
            r = False
        finally:
            return r

#DEFINE JUSDGEMENT CALL HELPER
#------------------------------
#IS THIS A HARD STATE
def isHardState(meta):
    hardStates = ['hard','HARD']
    if meta.servicestatetype in hardStates:
        return True
    else:
        return False

#DEFINE JUDGEMENT CALL HELPER
#------------------------------
#IS THIS A PROBLEM
def isProblem(meta):
    if meta.ccheck >= meta.mcheck:
        return True
    else:
        return False

#HOSTNAME IS NOT BLANK
def hasHostname(meta):
    if meta.hostname != "":
        return True
    else:
        return False

#COMPARE ORIGIN HOSTNAME TO A LIST OF HOSTNAMES TO EXCLUDE FROM FORWARDING EVENTS
def isBanList(meta):
    #BAN HOST LIST
    bannedHosts = ['localhost','LOCALHOST','hostname','HOSTNAME']

    if meta.hostname in bannedHosts:
        return True
    else:
        return False

#IS THIS SERVICE IN SCHEDULED DOWNTIME
#TODO EXTEND FOR HOST VS SERVICE TYPES
def isInDowntime(meta):
    if int(meta.downtime) > 0:
        return True
    else:
        return False

#--------------------------
#END JUDGEMENT CALL HELPER

#IN ORDER TO REDUCE ALERT FATIGUE WE CAN MAKE SOME PROGRAMATIC DECISIONS TO
#PRE-FILTER OUR EVENTS FOR ACTIONABILITY. USING AN EXTERNAL FUNCTION FOR EACH
#JUDGEMENT PROVIDES FOR EASY ADDITION/REMOVAL OF LOGICS  

#PASS JUDGEMENT
def makeJudgementCall(meta): 
    
    #JUDGEMENT CALL: IS THERE A HOSTNAME? (SHOULD BE HANDLED ARG INPUT, WE TRUS BUT VERUFY THAT)
    hashostname = hasHostname(meta)
    if hashostname:
        #JUDGEMENT CALL: IS HOSTNAME IN A BAN LIST?
        isbanned = isBanList(meta)
        if isbanned:
            #FAILED IS BANNED JUDGEMENT CALL
            logger.info("DISCARDED EVENT %s IS IN A SUPPRESSION LIST",meta.hostname)
            sys.exit()
        else:
            isvalid = True
    else:
        #FAILED HAS HOSTNAME JUDGEMEMT CALL
        #LOG AND EXIT
        logger.critical("HOSTNAME IS NOT PRESENT IN THE EVENT JUDGEMENT")
        sys.exit(2)
    
    #RETURN JUDGEMENT
    return isvalid

#HELPER FUNCTIONS#
#-----------------------------------------------------------------------------
#STATE SWITCHER HOST
def nagiosHostStateSwitcher(meta):    
    
    #HOST STATE ID
    i = meta.hoststateid
    
    #RETURN STATE BASED ON THE CURRENT HOSTSTATEID
    switcher = {
        #ID = STATE
        "0": "OK",
        "1": "DOWN",
        "2": "UNREACHABLE",
        "3": "UNKNOWN",
    }
    
    #DEBUG OUT
    if meta.debug:
        logger.debug("pid["+str(os.getpid())+"] host["+meta.hostname+"] hoststateid["+i+"]")
    
    #RETURN ACTION TYPE
    return switcher.get(i, False)

#STATE SWITCHER SERVICE
def nagiosServiceStateSwitcher(meta):    
    
    #SERVICE STATE ID
    i = meta.servicestateid
    
    #RETURN STATE BASED ON THE CURRENT SERVICESTATEID
    switcher = {
        #ID = STATE
        "0": "OK",
        "2": "CRITICAL",
        "1": "WARNING",
        "3": "UNKNOWN",
    }
    
    #DEBUG OUT
    if meta.debug:
        logger.debug("pid["+str(os.getpid())+"] host["+meta.hostname+"] servicestateid["+i+"]")
    
    #RETURN ACTION TYPE
    return switcher.get(i, False)


#HOST DEDUP KEY
def getDedupeKeyHost(i, meta):

    #RETURN PROBLEMID OR LAST PROBLEMID BASED ON EVENT TYPE
    switcher = {
        "PROBLEM": meta.hostname+"-"+meta.hostproblemid ,
        "FLLAPPINGSTART": meta.hostname+"-"+meta.hostproblemid ,
        "RECOVERY": meta.hostname+"-"+meta.lasthostproblemid,
        "FLAPPINGSTOP": meta.hostname+"-"+meta.lasthostproblemid
    }
    
    #DEBUG OUT
    if meta.debug:
        logger.debug("pid["+str(os.getpid())+"] eventType["+i+"] dedupKey["+str(switcher.get(i))+"]")
    
    #RETURN DEDUP KEY
    return switcher.get(i)

#SERVICE DEDUP KEY
def getDedupeKeyService(i, meta):

    #RETURN PROBLEMID OR LAST PROBLEMID BASED ON EVENT TYPE

    switcher = {
        "PROBLEM": meta.hostname+"-"+meta.serviceproblemid ,
        "FLAPPINGSTART": meta.hostname+"-"+meta.serviceproblemid ,
        "RECOVERY": meta.hostname+"-"+meta.lastserviceproblemid,
        "FLAPPINGSTOP": meta.hostname+"-"+meta.lastserviceproblemid
    }
    
    #DEBUG OUT
    if meta.debug:
        logger.debug("pid["+str(os.getpid())+"] eventType["+i+"] dedupKey["+str(switcher.get(i))+"]")
    
    #RETURN DEDUP KEY
    return switcher.get(i)

#PAYLOAD
#meta.ETYPE COMES FROM COMMAND INPUT AND WILL BE PULLED VIA META
#PROBLEM
#RECOVERY
#FLAPPINGSTART
#FLAPPINGSTOP
#DEDUPKEY IS HOST-NOTIFICATIONID/SERVICENOTIFICATIONID

#NOTIFICATION TYPE JUDGEMENT BASED ON PRESIOUS STATE AND CURRENT STATE
#USE NAGIOS CONTACT COMMAND

#IF NOTIFICATION TYPE = PROBLEM AND NOTIFICATION COUNT IS => 1
#THIS IS A NAGIOS ALERT

#IF NOTIFICATION TYPE = RECOVERY
#THIS IS A RESOLVE
#GET THE SYSID FROM THE COMMENTS AND SEND RECOVERY FOR THE INCIDENT
#CURRENT OUTPUT TO THE NOTES VS OVERWRITING THE DESCRIPTION

#IF NOTIFICATION TYPE = FLAPPINGSTART
#THIS IS NAGIOS A ALERT

#IF NOTIFICATION TYPE = FlAPPINGSTOP
#THIS IS A RECOVERY
#GET THE SYSID FROM THE COMMENTS AND SEND RECOVERY FOR THE INCIDENT
#CURRENT OUTPUT TO THE NOTES VS OVERWRITING THE DESCRIPTION

#ALL OTHER NOTIFICATION TYPES SHOULD DISCARD

def payloadManifest(dedupe_key,meta):
    #SERVICENOW STATE
    state = ""
    ###########################################################################
    #HOST
    ###########################################################################
    if meta.type == "host":        
        shortdesc = "{} | {} | {}".format(meta.hostname,meta.etype,"HOSTCHECK")
        #NEW ALERT
        if meta.etype == "PROBLEM":
            state = "1"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "event_action": meta.etype,
                "short_description": shortdesc,
                "cmdb_ci":meta.hostaddress,
                "category": "hardware",
                "subcategory": "Server",
                "business_service":"Business Service",
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        elif meta.etype == "FLAPPINGSTART":
            state = "1"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "event_action": meta.etype,
                "short_description": shortdesc,
                "cmdb_ci":meta.hostaddress,
                "category": "hardware",
                "subcategory": "Server",
                "business_service":"Business Service",
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        #RESOLVE
        elif meta.etype == "RECOVERY":
            state = "6"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "close_code":"Closed/Resolved by Caller",
                "close_notes":"Monitoring Service Recovery",
                "category": "hardware",
                "subcategory": "Server",
                "business_service":"Business Service",
                "event_action": meta.etype,
                "short_description": meta.hostname+"-hostcheck",
                "cmdb_ci":meta.hostaddress,
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        #RESOLVE
        elif meta.etype == "FLAPPINGSTOP":
            state = "6"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "close_code":"Closed/Resolved by Caller",
                "close_notes":"SERVICE HAS STOPPED FLAPPING",
                "category": "hardware",
                "subcategory": "Server",
                "business_service":"Business Service",
                "event_action": meta.etype,
                "short_description": meta.hostname+"-hostcheck",
                "cmdb_ci":meta.hostaddress,
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        #TYPE FILTER
        else:
            #DISCARD AS A DUPLICATE OR FILTERED ALERT
            print("Notification Type Discarded.")
            manifest = False
        #END HOST
                
    ############################################################################
    #SERVICE ALERT
    ############################################################################
    else:       
        shortdesc = "{} | {} | {}".format(meta.etype,meta.hostname,meta.source)
        #NEW ALERT
        if meta.etype == "PROBLEM":
            state = "1"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "event_action": meta.etype,
                "short_description": shortdesc,
                "business_service":"Business Service",
                "category": "software",
                "subcategory": "Performance",
                "cmdb_ci":meta.hostaddress,
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        #FLAPPING SERVICE
        #NEW ALERT
        elif meta.etype == "FLAPPINGSTART":
            state = "1"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "event_action": meta.etype,
                "short_description": shortdesc,
                "business_service":"Business Service",
                "category": "software",
                "subcategory": "Performance",
                "cmdb_ci":meta.hostaddress,
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        #RESOLVE SERVICE
        elif meta.etype == "RECOVERY":
            #PULL COMMENT DATA TO POPULATE SYSID/INCID
            state = "6"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "close_code":"Closed/Resolved by Caller",
                "close_notes":"Monitoring Service Recovery",
                "category": "software",
                "subcategory": "Performance",
                "service":"Business Service",
                "event_action": meta.etype,
                "short_description": shortdesc,
                "cmdb_ci":meta.hostaddress,
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        #RESOLVE SERVICE
        elif meta.etype == "FLAPPINGSTOP": 
            #PULL COMMENT DATA TO POPULATE SYSID/INCID
            state = "6"
            manifest = {
                "correlation_id": dedupe_key,
                "contact_type": "monitoring",
                "state": state,
                "close_code":"Closed/Resolved by Caller",
                "close_notes":"SERVICE HAS TOPPED FLAPPING",
                "category": "software",
                "subcategory": "Performance",
                "service":"Business Service",
                "event_action": meta.etype,
                "short_description": shortdesc,
                "cmdb_ci":meta.hostaddress,
                "description":meta.summary,
                "caller_id": "NagiosXI",
                "timestamp": None,
                "impact": meta.impact,
                "urgency": meta.urgency,
                "assignment_group": meta.changegroup,
                "work_notes": {
                    "time_in_state": meta.timeinstate,
                    "last_time_ok": meta.lasttimeok,
                    "last_time_critical": meta.lasttimecritical,
                    "nagios_notes": meta.notes
                }
            }
        #TYPE FILTERING
        else:
            #DISCARD EVENT
            print("Notification Type Discarded.")
            manifest = False
        
    #SERIALIZE THE MANIFEST DICT
    if manifest:
        payload = json.dumps(manifest)

        #DEBUG OUT
        if meta.debug:
            logger.debug("pid["+str(os.getpid())+"] eventType["+meta.etype+"] payload["+payload+"]")
    else:
        #WE DO NOT HAVE A MANIFEST WE WILL DISCARD
        print("DISCARDED DUE TO EMPTY MANIFEST")
        payload = False
        
    #SERVICENOW INCIDENT PAYLOAD
    return payload

#CREATE SERVICENOW INCIDENT
def sendEvent(payload):
    
    #API KEY FROM YAML
    config = serviceNowConfig(meta)

    #BASIC USERNAME AND PASSWORD AUTHENTICATION
    credentials = f"{config['user']}:{config['pass']}"
    base64_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {"Authorization": f"Basic {base64_credentials}"}

    #POST INCIDENT
    r = requests.post(url=config['url'],headers=headers,data=payload)

    if str(r.status_code) == "201":
        logger.info("pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(r.status_code)+"] Successfuly sent event to ServiceNow")
        result = r
    else:
        #FAILED WE EXIT
        logger.error("pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(r.status_code)+"] Failed with message "+str(r.text))
        sys.exit()
    
    #DEBUG OUT
    if meta.debug:
        print(r.text)
    
    #WE HAVE A SUCCESSFUL EVENT OR WE WOULD HAVE EXITIED
    return result

#UPDATE SERVICENOW INCIDENT
def updateEvent(meta,payload):
    
    #XI API KEY FROM CONFIGS
    config = serviceNowConfig(meta)
    
    #GET THE SYSID FROM COMMENTS
    comment = getSysID(meta)
    clist = comment.json()
    rc = clist['recordcount']
    
    #GET THE LATEST SYS_ID ONLY
    if rc > 0:
        c = clist['comment']
        i = 0
        if i < 1:
            sysid = c[0]['comment_data']
            logger.info("SYSID={}".format(sysid))
    else:
        sysid = ""

    #BASIC USERNAME AND PASSWORD AUTHENTICATION FOR SERVICE NOW
    credentials = f"{config['user']}:{config['pass']}"
    base64_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {"Authorization": f"Basic {base64_credentials}"}

    
    #PATCH INCIDENT WITH UPDATED INFORMATION
    rurl = "{}/{}".format(config['url'],sysid)
    r = requests.patch(url=rurl,headers=headers,data=payload)

    if str(r.status_code) == "200":
        logger.info("pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(r.status_code)+"] INCIDENT "+str(sysid)+" UPDATED")
        result = r
    else:
        #FAILED WE EXIT
        logger.error("pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(r.status_code)+"] "+str(sysid)+" UPDATE FAILED "+str(r.text))
        sys.exit()
    
    #DEBUG OUT
    if meta.debug:
        print(r.text)
    
    #UPDATE SUCCESSFUL EVENT OR WE WOULD HAVE EXITIED
    return result

#RESOLVE SERVICENOW INCIDENT
def resolveEvent(meta,payload):
    
    #XI API KEY FROM CONFIGS
    config = serviceNowConfig(meta)
    
    #GET THE SYSID FROM COMMENTS
    comment = getSysID(meta)
    clist = comment.json()
    rc = clist['recordcount']
    
    #GET THE LATEST SYS_ID ONLY
    if rc > 0:
        c = clist['comment']
        i = 0
        if i < 1:
            sysid = c[0]['comment_data']
            logger.info("SYSID={}".format(sysid))
    else:
        sysid = ""

    #BASIC USERNAME AND PASSWORD AUTHENTICATION FOR SERVICE NOW
    credentials = f"{config['user']}:{config['pass']}"
    base64_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {"Authorization": f"Basic {base64_credentials}"}

    
    #PATCH INCIDENT WITH UPDATED STATE
    rurl = "{}/{}".format(config['url'],sysid)
    r = requests.patch(url=rurl,headers=headers,data=payload)

    if str(r.status_code) == "200":
        logger.info("pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(r.status_code)+"] INCIDENT "+str(sysid)+" RESOLVED")
        result = r
    else:
        #FAILED WE EXIT
        logger.error("pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(r.status_code)+"] "+str(sysid)+" RESOLVE FAILED "+str(r.text))
        sys.exit()
    
    #DEBUG OUT
    if meta.debug:
        print(r.text)
    
    #CLOSE SUCCESSFUL EVENT OR WE WOULD HAVE EXITIED
    return result

##NAGIOSXI DIRECT GET API CALL
def nagiosxiGenericAPI(resource,endpoint,modifier,method,myurl,mykey):
    
    #URL FOR APICALL TO NAGIOSXI
    url = ("https://{turl}/nagiosxi/api/v1/{resource}/{endpoint}?{modifier}&apikey={akey}".format(turl=myurl,akey=mykey,resource=resource,endpoint=endpoint,modifier=modifier)) 

    #GET
    if method == "get":
        try:
            r = requests.get(url=url,verify=False)
        except Exception as e:
            logger.error("%s",e)
            r = False
    return r

#GET THE SERVICENOW SYSID FROM THE ACKNOWLEDGE COMMENT ON NAGIOSXI PROBLEM
def getSysID(meta):
    
    #NAGIOSXI API CREDS
    config = nagiosxiAPICreds(meta)

    if meta.type == "service":
        #ACK SEARCH STRING
        mstring = "host_name=lk:{}&service_description=lk:{}&sort=d".format(meta.hostname,meta.source)
    else:
        #HOST ACK SEARCH STRING
        mstring = "host_name={}&service_description=""&sort=d".format(meta.hostname)

    #URL FOR XI CORECOMMAND
    url = ("https://{turl}/nagiosxi/api/v1/{resource}/{endpoint}/?{modifier}&apikey={akey}".format(turl=config['url'],resource="objects",endpoint="comment",modifier=mstring,akey=config['apikey']))

    #GET COMMENTS FROM XI
    try:
        r = requests.get(url=url,verify=False)
    except Exception as e:
        logger.error("%s",e)
        r = False
    finally:
        return r

#ACKNOWLEDGE/COMMENT ON NAGIOSXI PROBLEM VIA API CALL
def nagAckent(pyld):
    
    #CREDS
    config = nagiosxiAPICreds(meta)
    
    #CONVERT OBJECT DEFINITION TO PAYLOAD
    payload = urllib.parse.urlencode(pyld)

    #URL FOR XI CORECOMMAND
    url = ("https://{turl}/nagiosxi/api/v1/{resource}/{endpoint}/?apikey={akey}".format(turl=config['url'],resource="system",endpoint="corecommand",akey=config['apikey']))
    
    #POST THE HOST CONFIG TO NAGIOSXI API
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    post = requests.post(url=url, data=payload, headers=headers, verify=False)
    
    if "success" in post.text:
        ack = True
    else:
        ack = False
    return ack

#SEND EVENT HOST
def handleEvent(meta):
    #SEND EVENT HOST
    if meta.type == "host":    
        #RETURN TRUE/FALSE
        if meta.etype == "RECOVERY":
            
            #USING THE SERVICE PROBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyHost(ntype,meta)

            #PAYLOAD OF RECOVERY PATCH
            payload = payloadManifest(dedupe_key, meta)
                    
            #SEND API REQUEST
            result = resolveEvent(meta,payload)

        elif meta.etype == "FLAPPINGSTOP":
            
            #USING THE SERVICE PROBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyHost(ntype,meta)

            #PAYLOAD OF RECOVERY PATCH
            payload = payloadManifest(dedupe_key, meta)
                    
            #SEND API REQUEST
            result = resolveEvent(meta,payload)

        elif meta.etype == "PROBLEM":
            #USING THE SERVICE RPOBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyHost(ntype,meta)

            #PAYLOAD OF PROBLEM NOTIFICATION
            payload = payloadManifest(dedupe_key, meta)
            
            #SEND API REQUEST
            result = sendEvent(payload)

        elif meta.etype == "FLAPPINGSTART":
            #USING THE SERVICE RPOBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyHost(ntype,meta)

            #PAYLOAD OF PROBLEM NOTIFICATION
            payload = payloadManifest(dedupe_key, meta)
            
            #SEND API REQUEST
            result = sendEvent(payload)

        else:
            #WE WERE GIVEN AN UNKNOWN EVENT TYPE WE EXIT
            logger.error("pid["+str(os.getpid())+"] Failed to handle returned eventType. eventType["+meta.etype+"] is unknown.")
            sys.exit()
        #DEBUG OUT
        if meta.debug:
            logger.debug(appName+"-DEBUG: pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(result.status_code)+"] result["+result.text+"]")    
        
        #RETURN RESULTS TO MAIN
        return result
    
    #SEND EVENT SERVICE
    else:
        if meta.etype == "RECOVERY":
            
            #USING THE SERVICE RPOBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyService(ntype,meta)
            
            #PAYLOAD OF RECOVERY
            payload = payloadManifest(dedupe_key, meta)
                    
            #SEND API REQUEST
            result = resolveEvent(meta,payload)
        elif meta.etype == "FLAPPINGSTOP":
            
            #USING THE SERVICE RPOBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyService(ntype,meta)
            
            #PAYLOAD OF RECOVERY
            payload = payloadManifest(dedupe_key, meta)
                    
            #SEND API REQUEST
            result = resolveEvent(meta,payload)
        elif meta.etype == "PROBLEM":
            #USING THE SERVICE RPOBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyService(ntype, meta)

            #PAYLOAD OF PROBLEM
            payload = payloadManifest(dedupe_key, meta)
            
            #SEND API REQUEST
            result = sendEvent(payload)
        elif meta.etype == "FLAPPINGSTART":
            #USING THE SERVICE RPOBLEMID AS THE DEDUP KEY ALLOWS US TO EASILY IDENTIFY
            #AND RETURN THE NEEDED UNIQUE VALUE REQUIRES
            ntype = meta.etype
            dedupe_key = getDedupeKeyService(ntype, meta)

            #PAYLOAD OF PROBLEM
            payload = payloadManifest(dedupe_key, meta)
            
            #SEND API REQUEST
            result = sendEvent(payload)
        else:
            #WE WERE GIVEN AN UNKNOWN EVENT TYPE WE EXIT
            logger.error("pid["+str(os.getpid())+"] Failed to handle returned eventType. eventType["+meta.etype+"] is unknown.")
            sys.exit()

    #DEBUG OUT
    if meta.debug:
        logger.debug(appName+"-DEBUG: pid["+str(os.getpid())+"] eventType["+meta.etype+"] statusCode["+str(result.status_code)+"] result["+result.text+"]")    
    
    #RETURN RESULTS TO MAIN
    return result

if __name__ == "__main__" :

    #OS PID FOR TRACING
    pid = os.getpid()

    event = argparse.ArgumentParser(prog=appName+" v:"+appVersion, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    #SERVICENOW EVNIRONMENT
    event.add_argument(
        "--senv",
        required=True,
        default="dev",
        help="String(ServiceNow Environment dev/prd): The ServiceNow Environment in which to create incidents."
    )
    #NAGIOSXI EVNIRONMENT
    event.add_argument(
        "--nenv",
        required=True,
        default="dev",
        help="String(NagiosXI Environment dev/prd): The NagiosXI Environment where comments are managed."
    )
    #ALERT DETAILS
    event.add_argument(
        "--type",
        required=True,
        default="service",
        help="String(Notificatioin Type): Either Service or Host."
    )
    #GLOBAL
    event.add_argument(
        "--etype",
        required=True,
        default=None,
        help="INT(notificationtype): The type of notification being sent. $HOSTNOTIFICATIONTYPE$/$SERVICENOTIFICATIONTYPE$"
    )
    #SERVICE FIELDS
    event.add_argument(
        "--lastservicestateid",
        required=False,
        default=None,
        help="INT(lastservicestateid): Numeric representation of the last service state observerd in Nagios (2,1,0,3)"
    )
    event.add_argument(
        "--servicestateid",
        required=False,
        default=None,
        help="INT(servicestateid): Numeric representation of the current service state observerd in Nagios (2,1,0,3)"
    )
    event.add_argument(
        "--serviceeventid",
        required=False,
        default=None,
        help="INT(serviceeventid): Unique identifier for the current service event id."
    )
    event.add_argument(
        "--serviceproblemid",
        required=False,
        default=None,
        help="INT(seviceproblemid): Unique identifier fir the current service problem id"
    )
    event.add_argument(
        "--lastserviceeventid",
        required=False,
        default=None,
        help="INT(lastserviceeventid): Unique identifier for the last service event id"
    )
    event.add_argument(
        "--lastserviceproblemid",
        required=False,
        default=None,
        help="INT(lastserviceproblemid): Unique id for the last service problem id."
    )
    
    #HOST FIELDS
    event.add_argument(
        "--lasthoststateid",
        required=False,
        default=None,
        help="INT(lasthoststateid): Numeric representation of the last host state observerd in Nagios (1,2,0,3)"
    )
    event.add_argument(
        "--hoststateid",
        required=False,
        default=None,
        help="INT(hoststateid): Numeric representation of the last host state observerd in Nagios (1,2,0,3)"
    )
    event.add_argument(
        "--hosteventid",
        required=False,
        default=None,
        help="INT(hosteventid): Unique identifier for the current host event id."
    )
    event.add_argument(
        "--hostproblemid",
        required=False,
        default=None,
        help="INT(seviceproblemid): Unique identifier fir the current service problem id"
    )
    event.add_argument(
        "--lasthosteventid",
        required=False,
        default=None,
        help="INT(lasthosteventid): Unique identifier for the last host event id"
    )
    event.add_argument(
        "--lasthostproblemid",
        required=False,
        default=None,
        help="INT(lasthostproblemid): Unique id for the last host problem id."
    )

    #GLOBAL
    event.add_argument(
        "--downtime",
        required=True,
        default=None,
        help="INT(servicedowntimedepth/hostdowntimedepth): Range between 0-X with zero being equal to no scheduled interruption."
    )

    event.add_argument(
        "--timeinstate",
        required=False,
        default=None,
        help="INT(timeinstate): The length of time in seconds that the service/host has been in the current state."
    )
    event.add_argument(
        "--lasttimeok",
        required=False,
        default=None,
        help="Timestamp(lasttimeok): The last time that the service/host was in the ok state."
    )
    event.add_argument(
        "--lasttimecritical",
        required=False,
        default=None,
        help="Timestamp(lasttimeceitical): The last time that the service/host was in the critical state."
    )
    event.add_argument(
        "--servicestatetype",
        required=False,
        default=None,
        help="String(servicesatetype): String value of either HARD or SOFT. Hard states result when service checks have been checked a specified maximum number of times."
    )
    event.add_argument(
        "--hostname",
        required=True,
        default=None,
        help="String($HOSTNAME$): The hostname to act on behalf of."
    )
    event.add_argument(
        "--hostaddress",
        required=True,
        default=None,
        help="String($HOSTADDRESS$): The host fqdn address."
    )
    event.add_argument(
        "--summary",
        required=False,
        default=None,
        help="String($SERVICEOUT$/$HOSTOUT$): A high-level, text summary message of the event. Will be used to construct an alert's description."
    )
    event.add_argument(
        "--impact",
        required=False,
        default=None,
        help="String($_SERVICEIMPACT$/$_HOSTIMPACT$): How impacted the affected system is. Displayed to users in lists and influences the priority of any created incidents. (1,2,3,4)"
    )
    event.add_argument(
        "--urgency",
        required=False,
        default=None,
        help="String($_SERVICEURGENCY$/$_HOSTURGENCY$): How urgent the affected item being reported. Displayed to users in lists and influences the priority of any created incidents. (1,2,3,4)"
    )
    event.add_argument(
        "--changegroup",
        required=True,
        default=None,
        help="String($_SERVICECHANGEGROUP$/$_HOSTCHANGEGROUP$): The ServiceNow Change Group responsible for stewardship of the service/host."
    )
    event.add_argument(
        "--source",
        required=False,
        default=None,
        help="String($SERVICEDESCRIPTION$/hostcheck): Specific human-readable unique identifier for the the problem. (Nagios Service Name/Host Alert)"
    )
    event.add_argument(
        "--notes",
        required=False,
        default=None,
        help="String($SERICENOTES$/$HOSTNOTES$): The notes that are associated to the service/host in nagios."
    )
    #TODO REMOVE ACK INPUT
    event.add_argument(
        "--ack",
        required=False,
        default=None,
        help="String($SERICEACKCOMMENT$/$HOSTACKCOMMENT$): The incidentID from service now that relates to the problem."
    )
    event.add_argument(
        "--debug",
        action="store_true",
        help="Boolean(StoreIfTrue): Set the flag to echo debug output to console and log."
    )

    #PARSE NAGIOS EVENT INPUT AND BUILD THE META ARRAY
    meta = event.parse_args()

    #DEAL WITH THE DEBUG
    if meta.debug:
        ch.setLevel(logging.DEBUG)
        fh.setLevel(logging.DEBUG)

    #PASS JUDGEMENT
    valid = makeJudgementCall(meta)
    
    if valid:
        #PERFORM ACTION BASED ON EVENT TYPE
        triggerList = ['PROBLEM','FLAPPINGSTART']
        recoveryList = ['RECOVERY','FLAPPINGSTOP']
        if meta.etype in triggerList:
            #TRIGGER NEW INCIDNET
            trigger = handleEvent(meta)
            sjson = trigger.json()
            #print(sjson)

            if trigger:
                logger.info("SEND INCIDENT TO SERVICENOW SUCCESS")
                author = "nagiosadmin"
                
                #SET UNIQUEID AS ACK MESSAGE
                msg = sjson['result']['sys_id']
                
                if meta.type.lower() == "service":
                    #NAGIOS ACK PAYLOAD
                    pyld = {
                            'cmd':'ACKNOWLEDGE_SVC_PROBLEM;{h};{d};{s};{n};{p};{a};{c}'.format(h=meta.hostname,d=meta.source,s="0",n="0",p="1",a=author,c=msg)
                            }
                else:
                    #NAGIOS ACK PAYLOAD
                    pyld = {
                            'cmd':'ACKNOWLEDGE_HOST_PROBLEM;{h};{s};{n};{p};{a};{c}'.format(h=meta.hostname,s="0",n="0",p="1",a=author,c=msg)
                            }
                    
                #POST ACK WIA API    
                postAck = nagAckent(pyld)
            
                #DEAL WITH RESPONSE
                if postAck:
                    logger.info("ACKNOWLEDGE PROBLEM SUCCESSFUL")
                    sys.exit()
                else:
                    logger.error("FAILED TO ACKNOWLEDGE PROBLEM")
                    sys.exit(2)
            else:
                logger.error("SEND INCIDENT TO SERVICENOW FAILED")
                sys.exit(2) 
        
        elif meta.etype in recoveryList:
            #SEND UPDATE EVENT
            resolve = handleEvent(meta)
            #TODO Prod testing
            #logger.info(resolve.text)
            logger.info(meta)
            logger.info("SERVICENOW INCIDENT RESOLUTION SENT")
        
        else:
            #THE RETURNED EVENT TYPE IS UNKNOW AND HAS FALLEN THOGUH OUR FILTERSWE WILL EXIT WITH FAILURE AND LOG
            #HANDLER INPUT TO HELP WITH TROUBLESHOOTING.
            logger.error("pid["+str(os.getpid())+"] NOTIFICATION TYPE NOT VALID FOR SERVICENOW.")
            sys.exit()
    else:
        #WE SHOULD NOT BE HERE
        #HANDLER INPUT TO HELP WITH TROUBLESHOOTING.
        logger.critical("pid["+str(os.getpid())+"]  Command input failed validity of judgement calls without exiting.")
        sys.exit()