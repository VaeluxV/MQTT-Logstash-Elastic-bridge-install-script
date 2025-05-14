#!/bin/bash

# Install script for setting up Mosquitto MQTT broker and Logstash for Elastic Cloud with easy configuration
# Requires: /
# Last updated: 2025-05-14
set -e

# Utility functions
generate_password() {
    tr -dc A-Za-z0-9 < /dev/urandom | head -c 16
}

ask_password() {
    local user_label=$1
    local pw
    echo "Choose password option for $user_label:"
    select opt in "Generate automatically" "Enter manually"; do
        case $REPLY in
            1)
                pw=$(generate_password)
                echo "Generated password for $user_label: $pw"
                break
                ;;
            2)
                while true; do
                    read -rsp "Enter password for $user_label: " pw
                    echo
                    read -rsp "Confirm password: " confirm_pw
                    echo
                    [[ "$pw" == "$confirm_pw" ]] && break
                    echo "Passwords do not match. Try again."
                done
                break
                ;;
            *)
                echo "Choose 1 or 2."
                ;;
        esac
    done
    echo "$pw"
}

prompt_nonempty() {
    local prompt="$1"
    local var
    while true; do
        read -rp "$prompt: " var
        [[ -n "$var" ]] && echo "$var" && return
        echo "Input cannot be empty!"
    done
}

echo "== MQTT to Elastic Installer =="

# User Inputs
mqtt_pub_user=$(prompt_nonempty "Enter MQTT publishing username (for devices)")
mqtt_pub_pass=$(ask_password "MQTT device user")

script_user=$(prompt_nonempty "Enter MQTT logging script username (used by the logger)")
script_pass=$(ask_password "Logger user (used to read and log to Elastic)")

elastic_cloud_id=$(prompt_nonempty "Enter your Elastic Cloud ID")
elastic_api_key=$(prompt_nonempty "Enter your Elastic API Key")

read -rp "Use per-sensor Elasticsearch indices? (y/n): " per_sensor_choice

# Confirm
echo -e "\n== Confirm Settings =="
echo "MQTT device username  : $mqtt_pub_user"
echo "Logger username       : $script_user"
echo "Elastic Cloud ID      : $elastic_cloud_id"
echo "Per-sensor indices    : $per_sensor_choice"
read -rp "Continue with setup? (y/n): " confirm
[[ "$confirm" != "y" ]] && exit 0

echo "== Installing Mosquitto MQTT =="
apt update
apt install -y mosquitto mosquitto-clients

# Setup Mosquitto config
mkdir -p /etc/mosquitto/conf.d
tee /etc/mosquitto/conf.d/auth.conf > /dev/null <<EOF
allow_anonymous false
password_file /etc/mosquitto/passwd
listener 1883
EOF

# Create MQTT users
touch /etc/mosquitto/passwd
chmod 640 /etc/mosquitto/passwd
mosquitto_passwd -b /etc/mosquitto/passwd "$mqtt_pub_user" "$mqtt_pub_pass"
mosquitto_passwd -b /etc/mosquitto/passwd "$script_user" "$script_pass"

# Logging
mkdir -p /var/log/mosquitto
touch /var/log/mosquitto/mosquitto.log
chown mosquitto: /var/log/mosquitto/mosquitto.log
chmod 644 /var/log/mosquitto/mosquitto.log

systemctl enable mosquitto
systemctl restart mosquitto

echo "== Installing Python 3.13 and Virtual Env =="
apt install -y software-properties-common
add-apt-repository ppa:deadsnakes/ppa -y
apt update
apt install -y python3.13 python3.13-venv python3.13-dev

echo "== Setting up Python MQTT Logger Script =="
mkdir -p /opt/mqtt_logger
cd /opt/mqtt_logger || exit
python3.13 -m venv venv
source venv/bin/activate
pip install paho-mqtt

# Logger script
cat > mqtt_logger.py <<EOF
import paho.mqtt.client as mqtt
import datetime

LOGFILE = "/var/log/mqtt_subscriber.log"
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_USER = """$script_user"""
MQTT_PASSWORD = """$script_pass"""
MQTT_TOPIC = "#"

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe(MQTT_TOPIC)

def on_message(client, userdata, msg):
    timestamp = datetime.datetime.now().isoformat()
    line = f"{timestamp} {msg.topic} {msg.payload.decode()}\\n"
    with open(LOGFILE, "a") as f:
        f.write(line)

client = mqtt.Client()
client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.loop_forever()
EOF

touch /var/log/mqtt_subscriber.log
chmod 644 /var/log/mqtt_subscriber.log
chown root:root /var/log/mqtt_subscriber.log

# Systemd service
cat > /etc/systemd/system/mqtt_logger.service <<EOF
[Unit]
Description=MQTT Logging Script
After=network.target

[Service]
ExecStart=/opt/mqtt_logger/venv/bin/python3.13 /opt/mqtt_logger/mqtt_logger.py
WorkingDirectory=/opt/mqtt_logger
User=root
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable mqtt_logger.service
systemctl start mqtt_logger.service

echo "== Installing Logstash (Elastic 8.x, compatible with Cloud 9.0.1) =="
apt install -y wget gnupg apt-transport-https
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt update
apt install -y logstash

mkdir -p /var/lib/logstash/plugins/inputs/file/
chown -R logstash:logstash /var/lib/logstash/plugins/

# Configure Logstash
logstash_config="/etc/logstash/conf.d/mqtt.conf"
filter_block=""
index_rule="mqtt-logs-%{+YYYY.MM.dd}"

if [[ "$per_sensor_choice" =~ ^[Yy]$ ]]; then
    index_rule="mqtt-logs-%{device_type}-%{+YYYY.MM.dd}"
    filter_block='
  mutate {
    add_field => { "device_type" => "%{[payload][device_type]}" }
  }

  mutate {
    lowercase => ["device_type"]
    gsub => [
      "device_type", "[^a-zA-Z0-9_-]", "-",
      "device_type", "-+", "-"
    ]
  }'
fi

cat > "$logstash_config" <<EOF
input {
  file {
    path => "/var/log/mqtt_subscriber.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/plugins/inputs/file/mqtt_log_sincedb"
  }
}

filter {
  grok {
    match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{DATA:topic} %{GREEDYDATA:raw_json}" }
  }

  date {
    match => ["timestamp", "ISO8601"]
  }

  json {
    source => "raw_json"
    target => "payload"
    skip_on_invalid_json => true
  }$filter_block
}

output {
  elasticsearch {
    cloud_id => "$elastic_cloud_id"
    api_key => "$elastic_api_key"
    ssl => true
    ssl_certificate_verification => false
    index => "$index_rule"
  }

  stdout {
    codec => rubydebug
  }
}
EOF

systemctl enable logstash
systemctl restart logstash

echo
echo "All done!"
echo "You might have to reboot the system for all changes to take effect correctly."
echo "You can publish MQTT messages to localhost:1883 using the '$mqtt_pub_user' user."
echo "The script user '$script_user' will log all messages to Elastic using your cloud config."
