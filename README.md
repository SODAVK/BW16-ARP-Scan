# BW16-ARP-Scan
ARP Scan in local network using BW16 (RTL8720DN)

# Hardware Requirements
- Ai-Thinker BW16 RTL8720DN Development Board

# Setup
1. Download Arduino IDE from [here](https://www.arduino.cc/en/software) according to your Operating System.
2. Install it.
3. Go to `File` → `Preferences` → `Additional Boards Manager URLs`.
4. Paste the following link :
   
   ```
   https://github.com/ambiot/ambd_arduino/raw/master/Arduino_package/package_realtek_amebad_index.json
   ```
5. Click on `OK`.
6. Go to `Tools` → `Board` → `Board Manager`.
7. Search `Realtek Ameba Boards (32-Bits ARM Cortex-M33@200MHz)` by `Realtek`.
!!! CODE WORK WITH 3.1.7 pack, other versions may not be work !!!
9. Install it.
10. Restart the Arduino IDE.
11. Done!

# Install
1. Download or Clone the Repository.
2. Open the folder and open `ARPScan.ino` in Arduino IDE.
3. Enter you data in: "WiFi.begin("u_ssid", "u_pass")"
4. Select board from the `Tools` → `Board` → `AmebaD ARM (32-bits) Boards`.
   - It is `Ai-Thinker BW16 (RTL8720DN)`.
5. Select the port of that board.
6. Go to `Tools` → `Board` → `Auto Flash Mode` and select `Enable`.
7. Upload the code.
   - Firmware will start working immediately.
   - Open Serial Monitor (115200) and write "scan"

# Note
Android/ios in sleep mode, may not be dont detected
TTL Scan may not work
Code for educational purposes, good luck
