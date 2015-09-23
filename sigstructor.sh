##########################################################################################################
#  Basic Snort/Suricata Rule creator. This script expects users to understand syntax of Snort/Suricata.  #
#  The GUI will accept whatever is input so use with prudence. No input validation at this time. This    #
#  code ain't pretty but It'll work in a pinch                                                           #
#                                                                                                        #
#  v1.0  R. Grubbs 'gambl3'  22 SEP 15                                                                   #
##########################################################################################################

#!/bin/bash 

## Snort path variables.. this is tuned for security onion for most installs it will be /etc/snort
SN_RULE_PATH="/etc/nsm/rules/local.rules"
SN_WHITE_LIST_PATH="/etc/nsm/rules/white_list.rules"
SN_BLACK_LIST_PATH="/etc/nsm/rules/black_list.rules"
SN_CONF="/etc/nsm/templates/snort/snort.conf"

## functions that that helps write desired rule type 
snort_type (){
  TYPE=$(zenity --entry --text "What type of rule is this? Valid options are "local" "whitelist" "blacklist"")
    case "$TYPE" in
	local)		snort_local ;;
	whitelist)	snort_white ;;
	blacklist)	snort_black ;;
	*)		zenity --error --text "Invalid input"  ;;
    esac
}
snort_white (){
  zenity --forms --title "Whitelist Rule" --text "Add IP to Whitelist" --separator " " --add-entry "IP Format: x.x.x.x/x" --add-entry "Description Format:  #comment"  >> "$SN_WHITE_LIST_PATH"
  nsm_sensor_ps-restart --only-snort-alert
}
snort_black (){
  zenity --forms --title "Blacklist Rule" --text "Add IP to Blacklist" --separator " " --add-entry "IP Format: x.x.x.x/x" --add-entry "Description Format:  #comment" >> "$SN_BLACK_LIST_PATH"
  nsm_sensor_ps-restart --only-snort-alert
}

##  function to make a rule for suricata this will grow quite a bit
snort_local (){
  zenity --info --text "Follow the wizard and input data according to the formats provided"
  ACTION=$(zenity --title "Rule Action" --entry --text " alert log") 
  PROTO=$(zenity --title "Rule Protocol" --entry --text "ip tcp udp icmp")
  SRC_IP=$(zenity --title "Source IP" --entry --text 'IP "$HOME__NET" "$EXTERNAL__NET" any')
  SRC_PORT=$(zenity --title "Source Port" --entry --text "port i.e. 25 or any") 
  DIR=$(zenity --title "Flow Direction" --entry --text "For -> or <>")
  DST_IP=$(zenity --title "Destination IP" --entry --text 'IP "$HOME__NET" "$EXTERNAL__NET" any')
  DST_PORT=$(zenity --title "Destination IP" --entry --text "port i.e. 25 or any ")
  MSG=$(zenity --title "Snort Message" --entry --text '(msg: "Description";')
 #DEPTH --TO DO write in advanced options
 #OFFSET -- TO DO write in advance options
  CONTENT=$(zenity --title "Content Match" --entry --text 'content: "Content to match; not tested with PCRE";') ## TO DO test with PCRE
  SID=$(zenity --title "Rule SID" --entry --text 'sid: 100000;)')
  
  if zenity --question --ok-label "Correct" --cancel-label "Incorrect" --title "Is Snort Rule Correct?" --text ""$ACTION" "$PROTO" "$SRC_IP" "$SRC_PORT" "$DIR" "$DST_IP" "$DST_PORT" "$MSG" "$CONTENT" "$SID""; then
 echo "$ACTION" "$PROTO" "$SRC_IP" "$SRC_PORT" "${DIR}" "$DST_IP" "$DST_PORT" "$MSG" "$CONTENT" "$SID" > /tmp/rule
  else
    zenity --warning --text "Fix it then"
    exit 2
  fi
  
  /bin/cat /tmp/rule  >> "$SN_RULE_PATH"        ## Put new rule in rule path then testing 
  snort -T -c "$SN_CONF" -l /tmp                ## Test configuration, used a dummy log location for portability
  if [ $? == 0 ]; then                          ## If return value of test is good write rule and clean up /tmp/rule  
     rm -rf /tmp/rule
     nsm_sensor_ps-restart --only-snort-alert   ## Restart snort service
  else
     zenity --error --text "The rule you added failed; check your rule for errors"
     rm -rf /tmp/rule                           ##  Cleanup temp file path
     tail -n 1 "$SN_RULE_PATH" | wc -c |xargs -I {} truncate "$SN_RULE_PATH" -s -{}  ## Remove bad rule we just added 
  fi
}

##  function to make a suricata rule need to find a way to make this accurate  
suri_local (){
  zenity --info --text "Follow the wizard and input data according to the formats provided"
  ACTION=$(zenity --title "Rule Action" --entry --text " alert log") 
  PROTO=$(zenity --title "Rule Protocol" --entry --text "ip tcp udp icmp")
  SRC_IP=$(zenity --title "Source IP" --entry --text 'IP "$HOME__NET" "$EXTERNAL__NET" any')
  SRC_PORT=$(zenity --title "Source Port" --entry --text "port i.e. 25 or any") 
  DIR=$(zenity --title "Flow Direction" --entry --text "For -> or <>")
  DST_IP=$(zenity --title "Destination IP" --entry --text 'IP "$HOME__NET" "$EXTERNAL__NET" any')
  DST_PORT=$(zenity --title "Destination IP" --entry --text "port i.e. 25 or any ")
  MSG=$(zenity --title "Snort Message" --entry --text '(msg: "Description";')
 #DEPTH --TO DO write in advanced options
 #OFFSET -- TO DO write in advance options
  CONTENT=$(zenity --title "Content Match" --entry --text 'content: "Content to match; not tested with PCRE";') ## TO DO test with PCRE
  SID=$(zenity --title "Rule SID" --entry --text 'sid: 100000;)')
  
  if zenity --question --ok-label "Correct" --cancel-label "Incorrect" --title "Is Snort Rule Correct?" --text ""$ACTION" "$PROTO" "$SRC_IP" "$SRC_PORT" "${DIR}" "$DST_IP" "$DST_PORT" "$MSG" "$CONTENT" "$SID""; then
 echo "$ACTION" "$PROTO" "$SRC_IP" "$SRC_PORT" "${DIR}" "$DST_IP" "$DST_PORT" "$MSG" "$CONTENT" "$SID" > /tmp/rule
  else
    zenity --warning --text "Fix your rule by running the script again"
    exit 2
  fi
}

##  ask the user what IDS this is for
IDS=$(zenity --entry --text "Is this a rule for snort or suricata IDS?")

##  based on answer call the appropriate function. if incorrect answer exit with error
    case "$IDS" in 
      	suricata)  suri_new ;;
      	snort)	   snort_type ;;
	*)	   zenity --error --text  "Usage -- enter <b>snort</b> or <b>suricata</b> to make a rule. exiting"; exit ;;
   
    esac
 
