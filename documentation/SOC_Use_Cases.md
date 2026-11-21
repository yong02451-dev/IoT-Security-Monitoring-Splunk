# SOC Use Cases – IoT Security Monitoring with Splunk

## 1. RFID Authentication Monitoring

**Objective:** Monitor successful and failed RFID authentication attempts.

**Splunk Search:**

```spl
index=rfid_auth (event_type="AUTH_SUCCESS" OR event_type="AUTH_FAILED")
| timechart span=5m count by event_type
```

**What a SOC Analyst Monitors:**
- Successful card authentication.
- Failed card authentication.
- Changes in authentication activity over time.

**Security Relevance:** Repeated failed attempts may indicate someone trying unauthorized RFID cards.

## 2. Repeated Failed Access Attempts

**Objective:** Identify repeated unsuccessful RFID authentication attempts.

**Splunk Search:**

```spl
index=rfid_auth event_type="AUTH_FAILED"
| bin _time span=5m
| stats count as failed_attempts by _time device
| where failed_attempts > 3
| table _time device failed_attempts
| sort - failed_attempts
```

**What a SOC Analyst Investigates:**
- Number of failed attempts.
- Time window in which failures occurred.
- Whether repeated attempts are unusual.

**Security Relevance:** Multiple failed attempts within a short period may indicate unauthorized access activity.

**Detection Threshold:** More than 3 failed attempts within 5 minutes.

## 3. IoT Device Health Monitoring

**Objective:** Monitor whether the IoT device is regularly sending heartbeat events.

**Splunk Search:**

```spl
index=rfid_auth event_type="DEVICE_HEARTBEAT" earliest=-24h
| stats latest(_time) as last_heartbeat
| eval seconds_since_heartbeat=round(now()-last_heartbeat,0)
| eval device_status=if(seconds_since_heartbeat>90,"OFFLINE","ONLINE")
| convert ctime(last_heartbeat)
| table device_status last_heartbeat seconds_since_heartbeat
```

**What a SOC Analyst Monitors:**
- Last received heartbeat.
- Time elapsed since the last heartbeat.
- Whether the device has exceeded the 90-second threshold.

**Security Relevance:** A device that stops reporting may have lost power, connectivity, or become unavailable.

**Detection Threshold:** More than 90 seconds since the last heartbeat.

## 4. Wi-Fi Disconnection Monitoring

**Objective:** Identify repeated Wi-Fi disconnection events.

**Splunk Search:**

```spl
index=rfid_auth event_type="WIFI_DISCONNECTED"
| bin _time span=1m
| stats count as disconnect_count by _time device
| where disconnect_count >= 3
| table _time device disconnect_count
| sort - disconnect_count
```

**What a SOC Analyst Investigates:**
- Frequency of disconnection events.
- Whether disconnections happen repeatedly.
- Whether connectivity is restored.

**Security Relevance:** Repeated disconnections may indicate network instability or suspicious connectivity interruptions.

**Detection Threshold:** 3 or more disconnection events within one minute.

**Important Limitation:** A Wi-Fi disconnection event alone does not prove a deauthentication attack. Additional wireless network monitoring is needed to determine the cause.

## 5. Conclusion

These use cases demonstrate how Splunk can be used to monitor IoT security events, investigate suspicious authentication activity, and track device availability and network connectivity.

The searches provide a foundation for SOC monitoring and can be extended with dashboards, scheduled alerts, and additional network telemetry.