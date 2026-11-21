#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <SPI.h>
#include <MFRC522.h>
#include <EEPROM.h>
#include <Servo.h>

// ==========================================
// 1. WIFI CONFIGURATION
// ==========================================

const char* WIFI_SSID = "";
const char* WIFI_PASSWORD = "";


unsigned long lastHeartbeat = 0;
const unsigned long HEARTBEAT_INTERVAL = 30000; // 30 seconds

// Wi-Fi monitoring variables
bool wifiWasConnected = false;
bool wifiDisconnectPending = false;

unsigned long wifiDisconnectTime = 0;


// ==========================================
// 2. SPLUNK HEC CONFIGURATION
// ==========================================

const char* SPLUNK_IP = "10.95.73.67";
const int SPLUNK_PORT = 8088;

const char* HEC_TOKEN = "";

const char* HEC_FINGERPRINT =
"97:E9:40:1B:B8:4B:61:47:09:9F:1F:12:93:98:99:8A:ED:2D:F2:0B";

const char* SPLUNK_INDEX = "rfid_auth";

// ==========================================
// 3. RFID CONFIGURATION
// ==========================================

#define SS_PIN D2
#define RST_PIN D1

MFRC522 rfid(SS_PIN, RST_PIN);

// ==========================================
// 4. SERVO CONFIGURATION
// ==========================================

#define SERVO_PIN D4

Servo doorServo;

const int LOCK_POSITION = 0;
const int UNLOCK_POSITION = 90;

const unsigned long UNLOCK_TIME = 4000;

// ==========================================
// 5. EEPROM CONFIGURATION
// KEEP SAME AS REGISTRATION PROGRAM
// ==========================================

#define EEPROM_SIZE 512
#define MAX_USERS 10

const int COUNT_ADDRESS = 0;
const int USER_START_ADDRESS = 1;

struct User {
  char uid[21];
  char name[24];
};

// ==========================================
// 6. JSON ESCAPING
// ==========================================

String escapeJSON(const char* input) {

  String output = "";

  while (*input) {

    char c = *input++;

    if (c == '"' || c == '\\') {
      output += '\\';
      output += c;
    }
    else if (c == '\n') {
      output += "\\n";
    }
    else if (c == '\r') {
      output += "\\r";
    }
    else if ((unsigned char)c >= 32) {
      output += c;
    }
  }

  return output;
}

// ==========================================
// 7. WIFI CONNECTION
// ==========================================

bool connectWiFi() {

  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  Serial.println("\nConnecting to Wi-Fi...");

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long startTime = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - startTime < 20000) {

    delay(500);
    Serial.print(".");
  }

  if (WiFi.status() == WL_CONNECTED) {

    Serial.println("\nWi-Fi connected!");

    Serial.print("IP Address: ");
    Serial.println(WiFi.localIP());

    return true;
  }

  Serial.println("\nWi-Fi connection failed!");

  return false;
}

// ==========================================
// 8. SEND EVENT TO SPLUNK
// ==========================================

bool sendToSplunk(
  const char* eventType,
  const char* uid,
  const char* username
) {

  if (!connectWiFi()) {
    Serial.println("Splunk event not sent: Wi-Fi unavailable");
    return false;
  }

  BearSSL::WiFiClientSecure client;

  client.setTimeout(5000);

  // Verify the exact Splunk server certificate.
  if (!client.setFingerprint(HEC_FINGERPRINT)) {

    Serial.println("Invalid certificate fingerprint!");

    return false;
  }

  Serial.println("\nConnecting to Splunk HEC...");

  if (!client.connect(SPLUNK_IP, SPLUNK_PORT)) {

    Serial.println("Splunk TLS connection failed!");

    char errorMessage[160];

    int errorCode = client.getLastSSLError(
      errorMessage,
      sizeof(errorMessage)
    );

    Serial.print("TLS error: ");
    Serial.println(errorMessage);

    return false;
  }

  // Build the event JSON.
  String event = "{";

  event += "\"device\":\"NodeMCU_RFID\",";
  event += "\"event_type\":\"";
  event += eventType;
  event += "\",";

  event += "\"uid\":\"";
  event += uid;
  event += "\",";

  event += "\"username\":\"";
  event += escapeJSON(username);
  event += "\"";

  event += "}";

  String payload = "{";

  payload += "\"index\":\"";
  payload += SPLUNK_INDEX;
  payload += "\",";

  payload += "\"sourcetype\":\"_json\",";
  payload += "\"event\":";
  payload += event;

  payload += "}";

  // Send HTTP POST request.
  client.println(
    "POST /services/collector/event HTTP/1.1"
  );

  client.println("Host: 10.95.73.67:8088");

  client.print("Authorization: Splunk ");
  client.println(HEC_TOKEN);

  client.println("Content-Type: application/json");

  client.print("Content-Length: ");
  client.println(payload.length());

  client.println("Connection: close");
  client.println();

  client.print(payload);

  Serial.println("Event sent to Splunk:");
  Serial.println(payload);

  // Read HTTP response.
  unsigned long startTime = millis();

  while (!client.available() &&
         client.connected() &&
         millis() - startTime < 10000) {

    delay(10);
  }

  String response = "";

  while (client.available()) {
    response += (char)client.read();
  }

  client.stop();

  Serial.println("\nSplunk response:");
  Serial.println(response);

  if (response.indexOf("\"code\":0") >= 0) {

    Serial.println("Splunk accepted the event!");

    return true;
  }

  Serial.println("Splunk did not confirm event acceptance.");

  return false;
}

// ==========================================
// 9. GET RFID UID
// ==========================================

String getCardUID() {

  String uid = "";

  for (byte i = 0; i < rfid.uid.size; i++) {

    if (rfid.uid.uidByte[i] < 0x10) {
      uid += "0";
    }

    uid += String(rfid.uid.uidByte[i], HEX);
  }

  uid.toUpperCase();

  return uid;
}

// ==========================================
// 10. AUTHENTICATE RFID USER
// ==========================================

bool authenticateUser(
  String scannedUID,
  char* username
) {

  byte userCount = EEPROM.read(COUNT_ADDRESS);

  if (userCount > MAX_USERS) {

    Serial.println("EEPROM user count is invalid!");

    return false;
  }

  for (int i = 0; i < userCount; i++) {

    User user;

    int address =
      USER_START_ADDRESS + (i * sizeof(User));

    EEPROM.get(address, user);

    user.uid[20] = '\0';
    user.name[23] = '\0';

    if (scannedUID.equals(user.uid)) {

      strncpy(username, user.name, 24);

      username[23] = '\0';

      return true;
    }
  }

  return false;
}

// ==========================================
// 11. DOOR UNLOCK
// ==========================================

void unlockDoor() {

  Serial.println("\nACCESS GRANTED");

  doorServo.write(UNLOCK_POSITION);

  Serial.println("Door unlocked!");

  delay(UNLOCK_TIME);

  doorServo.write(LOCK_POSITION);

  Serial.println("Door locked!");
}

// ==========================================
// 12. SETUP
// ==========================================

void setup() {

  Serial.begin(115200);

  delay(1000);

  Serial.println("\n================================");
  Serial.println(" RFID SMART DOOR LOCK SYSTEM");
  Serial.println(" NodeMCU + RC522 + Servo + Splunk");
  Serial.println("================================");

  // Initialize EEPROM.
  EEPROM.begin(EEPROM_SIZE);

  // Initialize SPI and RFID.
  SPI.begin();

  rfid.PCD_Init();

  // Initialize servo.
  doorServo.attach(SERVO_PIN);

  doorServo.write(LOCK_POSITION);

  Serial.println("RFID reader initialized.");
  Serial.println("Servo initialized.");
  Serial.println("Door status: LOCKED");

  // Connect Wi-Fi.
  if (connectWiFi()) {

    wifiWasConnected = true;

    sendToSplunk(
      "DEVICE_BOOT",
      "NONE",
      "SYSTEM"
    );

    sendToSplunk(
    "WIFI_CONNECTED",
    "NONE",
    "SYSTEM"
    ); 
  }
}

// ==========================================
// 13. MAIN LOOP
// ==========================================

void loop() {

  monitorWiFi();

  sendHeartbeat();
  // Reconnect Wi-Fi if disconnected.
  if (WiFi.status() != WL_CONNECTED) {

    connectWiFi();
  }

  // Wait for RFID card.
  if (!rfid.PICC_IsNewCardPresent()) {
    delay(50);
    return;
  }

  if (!rfid.PICC_ReadCardSerial()) {
    delay(50);
    return;
  }

  // Read UID.
  String scannedUID = getCardUID();

  Serial.println("\n================================");
  Serial.println("RFID CARD DETECTED");
  Serial.print("UID: ");
  Serial.println(scannedUID);

  char username[24] = "UNKNOWN";

  // Authenticate.
  bool authenticated = authenticateUser(
    scannedUID,
    username
  );

  if (authenticated) {

    Serial.println("ACCESS GRANTED");

    Serial.print("Welcome, ");
    Serial.println(username);

    // Unlock door and then lock it again.
    unlockDoor();

    // Send successful authentication event.
    sendToSplunk(
      "AUTH_SUCCESS",
      scannedUID.c_str(),
      username
    );

    // Send door state events.
    sendToSplunk(
      "DOOR_UNLOCKED",
      scannedUID.c_str(),
      username
    );

    sendToSplunk(
      "DOOR_LOCKED",
      scannedUID.c_str(),
      username
    );

  }
  else {

    Serial.println("ACCESS DENIED");

    Serial.println("Unknown RFID card!");

    // Send failed authentication event.
    sendToSplunk(
      "AUTH_FAILED",
      scannedUID.c_str(),
      "UNKNOWN"
    );
  }

  // Stop communication with the card.
  rfid.PICC_HaltA();

  rfid.PCD_StopCrypto1();

  Serial.println("================================");

  delay(1000);
}

void sendHeartbeat() {

  if (millis() - lastHeartbeat >= HEARTBEAT_INTERVAL) {

    lastHeartbeat = millis();

    sendToSplunk(
      "DEVICE_HEARTBEAT",
      "",
      ""
    );

    Serial.println("Heartbeat sent to Splunk");
  }
}

void monitorWiFi() {

  // Check if Wi-Fi is disconnected
  if (WiFi.status() != WL_CONNECTED) {

    if (wifiWasConnected) {

      wifiWasConnected = false;
      wifiDisconnectPending = true;
      wifiDisconnectTime = millis();

      Serial.println("WARNING: Wi-Fi disconnected!");
    }

    return;
  }

  // Wi-Fi is connected again
  if (!wifiWasConnected) {

    wifiWasConnected = true;

    if (wifiDisconnectPending) {

      unsigned long duration =
        (millis() - wifiDisconnectTime) / 1000;

      Serial.println("Wi-Fi reconnected!");

      Serial.print("Disconnection duration: ");
      Serial.print(duration);
      Serial.println(" seconds");

      sendToSplunk(
        "WIFI_DISCONNECTED",
        "NONE",
        "SYSTEM"
      );

      sendToSplunk(
        "WIFI_RECONNECTED",
        "NONE",
        "SYSTEM"
      );

      wifiDisconnectPending = false;
    }
  }
}