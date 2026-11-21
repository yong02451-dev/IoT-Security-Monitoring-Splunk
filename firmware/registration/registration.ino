void loop() {

  // PRIORITY 1: Read username
  if (waitingForName && Serial.available()) {

    String name = Serial.readStringUntil('\n');
    name.trim();

    if (name.length() > 0) {
      registerUser(pendingUID, name);
      waitingForName = false;
      pendingUID = "";
    }

    return;
  }

  // PRIORITY 2: Read commands
  if (!waitingForName && Serial.available()) {

    String command = Serial.readStringUntil('\n');
    command.trim();
    command.toUpperCase();

    if (command == "SCAN") {
      waitingForCard = true;
      Serial.println("Place RFID card near reader...");
    }
    else if (command == "LIST") {
      listUsers();
    }
    else if (command == "CANCEL") {
      waitingForCard = false;
      Serial.println("Registration cancelled.");
    }
  }

  // Keep your existing RFID card detection code here.
}