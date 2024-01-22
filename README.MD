| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C6 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | -------- |

# ESP-IDF Template

This is a template application for using Wifi Station | Wifi SoftAP | Ethernet with TCP IP Stack. This is to be used with Espressif IoT Development Framework.

Please check ESP-IDF docs for getting started instructions.

Code in this repository is in the Public Domain (or CC0 licensed, at your option.) Unless required by applicable law or agreed to in writing, this software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

### About mDNS

The IP address of an IoT device may vary from time to time, so it’s impracticable to hard code the IP address in the webpage. In this template-project, we use the `mDNS` to parse the domain name `esp-home.local`, so that we can alway get access to the web server by this URL no matter what the real IP address behind it. See [here](https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/protocols/mdns.html) for more information about mDNS.

**Notes: mDNS is installed by default on most operating systems or is available as separate package.**

### Hardware Required

To run this template-project, you need an ESP32 dev board (e.g. ESP32-WROVER Kit, ESP32-Ethernet-Kit) or ESP32 core board (e.g. ESP32-DevKitC). An extra JTAG adapter might also needed if you choose to deploy the website by semihosting. For more information about supported JTAG adapter, please refer to [select JTAG adapter](https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/jtag-debugging/index.html#jtag-debugging-selecting-jtag-adapter). Or if you choose to deploy the website to SD card, an extra SD slot board is needed.
