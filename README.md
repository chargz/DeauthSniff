# DeauthSniff

DeauthSniff alerts users about potential WiFi deauthentication attacks. 

 Your Wireless Adapter must support Monitor Mode for this project to work. 
 To set your interface to monitor mode, assuming it is `wlan0`:
 - `sudo ifconfig wlan0 down`
  - `sudo iwconfig wlan0 mode monitor`
  - `sudo ifconfig wlan0 up`

# Installation

  - Run `sudo apt-get install libpcap-dev`
  - Compile the project using `gcc ./deauthsniff.c -lpcap -o deauth -ggdb`
  - To run the project, `sudo ./deauth <WIRELESS INTERFACE>` (Should be in Monitor Mode)


The project is a modified version of weaknetlab's project '802.11-libpcap-c'. Check them out here: https://github.com/weaknetlabs
