# RogueAP
Rogue Wi-Fi Access Point (AP) detection tool

PCI DSS and HITRUST  frameworks require to detect and identify all authorized and unauthorized wireless (802.11) access points (APs) at company sites. The goal of this project is to develop a tool to perform such detection in multiple location.  
Definition of a Rogue AP: an AP(s) transmitting one of company's SSID(s) and that is not under company's control identified by a MAC address or BSSID

The solution should contain the following elements:
* A service (daemon) or a scheduled job scanning  the 802.11x channels to enumerate active SSIDs and MACs/BSSIDs pairs
* Filter enumerated pairs to only company controlled SSIDs 
* For filtered pairs exclude known/authorized MACs/BSSIDs 
* Report to the Security Operation center (SOC) all unknown MACs/BSSIDs as rogue APs

We'll use Python