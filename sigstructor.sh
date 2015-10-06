##########################################################################################################
#  Basic Snort/Suricata Rule creator. This script expects users to understand syntax of Snort/Suricata.  #
#  The GUI will accept whatever is input so use with prudence. No input validation at this time. This    #
#  code ain't pretty but It'll work to make a basic rule in a pinch                                      #
#                                                                                                        #
#                                                                                                        #
#  v1.0  R. Grubbs 'gambl3'  6 October 15                                                                #
##########################################################################################################

#!/bin/bash 

## Snort path variables.. this is tuned for security onion for most installs it will be /etc/snort
SN_RULE_PATH="/etc/nsm/rules/local.rules"
SN_WHITE_LIST_PATH="/etc/nsm/rules/white_list.rules"
SN_BLACK_LIST_PATH="/etc/nsm/rules/black_list.rules"
SN_CONF="/etc/nsm/templates/snort/snort.conf"

## functions that that helps write desired rule type 
snort_type (){
  TYPE=$(zenity --entry --text "What type of rule is this? Valid options are:   "local"   "whitelist"   "blacklist"")
    case "$TYPE" in
	local)		snort_local ;;
	whitelist)	snort_white ;;
	blacklist)	snort_black ;;
	*)		zenity --error --text "Invalid input"  ;;
    esac
}
snort_white (){
  zenity --forms --title "Whitelist Rule" --text "Add IP to Whitelist" --separator " " --add-entry "IP Format: x.x.x.x/x" --add-entry "Description Format:  #comment"  >> "$SN_WHITE_LIST_PATH"
  if [ $? == "0" ]; then
    rule-update
  else
    zenity --error --text "Operation Canceled"
  fi 
}
snort_black (){
  zenity --forms --title "Blacklist Rule" --text "Add IP to Blacklist" --separator " " --add-entry "IP Format: x.x.x.x/x" --add-entry "Description Format:  #comment" >> "$SN_BLACK_LIST_PATH"
  if [ $? == "0" ]; then
    rule-update
  else
    zenity --error --text "Operation Canceled"
  fi
}
snort_local (){                    
  ## zenity form for basic rules.  Not tested with PCRE or advanced options                                            
  zenity --forms --title "Snort Local Rule" --text "Make Rule" --separator " "  \
	--add-entry "Rule Action: alert or log" 				\
	--add-entry "Rule Protocol: tcp udp icmp"				\
	--add-entry 'Source IP: x.x.x.x $HOME__NET $EXTERNAL__NET any' 		\
	--add-entry "Source Port: port number or any"  				\
	--add-entry "Flow Direction: ->   <>" 					\
	--add-entry 'Destination IP: x.x.x.x $HOME__NET $EXTERNAL__NET any' 	\
	--add-entry "Destination Port: port number or any"  			\
	--add-entry 'Message: (msg: "Message";'					\
	--add-entry 'Content: content: "content to search for or negate";' 	\
	--add-entry 'Signature ID:  sid: 100000;)' >> /tmp/random 
  
  if [ $? == 0 ]; then
	zenity --question --text "Your rule is `cat /tmp/random`. Do you want it to be written to "$SN_RULE_PATH"" ## Shows rule for validation
     if [ $? == 0 ]; then                                   ## If user accepts rule put rule in path and test  
        echo `tail -n 1 /tmp/random` >> "$SN_RULE_PATH"
        snort -T -c "$SN_CONF" -l /tmp                      ## Test configuration, used a dummy log location for portability. If rules passes it only means it won't break snort
  	  if [ $? == 0 ]; then	                            ## Check return value of snort test for errors
	    rule-update                                     ## Run pulled pork which will restart snort service
	    rm -rf /tmp/random
	  else
	    zenity --error --text "The rule you added failed; check your rule for errors"
	    tail -n 1 "$SN_RULE_PATH" | wc -c |xargs -I {} truncate "$SN_RULE_PATH" -s -{}  ## Remove bad rule we just added 
	    rm -rf /tmp/random
          fi
     else 
       zenity --error --text "Run script again to adjust inputs" 
       rm -rf /tmp/random
     fi
  else
    zenity --warning --text "Operation Canceled"
  fi
}

##  TO DO function to make a suricata rule..This will look shockingly similar to snort I imagine   

##  ask the user what IDS this is for
IDS=$(zenity --entry --text "Is this a rule for snort or suricata IDS?")

##  based on answer call the appropriate function. if incorrect answer exit with error
    case "$IDS" in 
      	suricata)  suri_type ;;
      	snort)	   snort_type ;;
	*)	   zenity --error --text  "Usage -- enter <b>snort</b> or <b>suricata</b> to make a rule. exiting"; exit ;;
   
    esac
