# sigstructor
Bash script for creating simple snort and suricata rules in Security Onion. Really meant for entry level personnel to help guide them until they are more familiar with rules and text editors. This script is very beta and comes with no guarantee that it will fit your needs. Currently uses Zenity to provide a GUI for entering IDS rule variables then places the rule in the appropriate location, tests and restarts the service. The script is only as good as the rule you write. The rule isn't tested for rate of detection only that it will/will not break snort when the rule is added to the rule path. 


