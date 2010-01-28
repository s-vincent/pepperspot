#!/bin/bash

# Setting ath0 in Master mode
# Replace !PepperSpot by your SSID

wlanconfig ath0 destroy
wlanconfig ath0 create wlandev wifi0 wlanmode ap
iwconfig ath0 essid "PepperSpot"	
ifconfig ath0 up
