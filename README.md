# MQTT → Logstash → Elastic bridge install script

A script that aids in installing and configuring an MQTT server, the data of which gets sent to an Elastic cloud instance through a small Python script and Logstash.

Run the script:
```bash
curl -s -o mqtt_logstash_installer.sh https://raw.githubusercontent.com/VaeluxV/MQTT-Logstash-Elastic-bridge-install-script/refs/heads/main/mqtt_logstash_install.sh && sudo bash mqtt_logstash_installer.sh && rm mqtt_logstash_installer.sh
```

Get just the script:
```bash
curl -s -o mqtt_logstash_installer.sh https://raw.githubusercontent.com/VaeluxV/MQTT-Logstash-Elastic-bridge-install-script/refs/heads/main/mqtt_logstash_install.sh
```

This will put the script in the location you are in a file named `mqtt_logstash_installer.sh`

---

If the install fails for some reason, try again. If that does not work try rebooting the system and seeing if it works after.

> Tested on a clean install ubuntu server 24.04 LTS with SSH only. I cannot guarantee this will work on other systems.

*The usecase for this script is pretty specific. However it is now here if you need it!*

~ Valerie