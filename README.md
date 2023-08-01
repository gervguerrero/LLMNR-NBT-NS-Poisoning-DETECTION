# 🔵 LLMNR-NBT-NS-Poisoning-DETECTION 🔵

This project is a sub-project to: 

[ESXi-Home-SOC-Lab-Network-Overview](https://github.com/gervguerrero/ESXi-Home-SOC-Lab-Network-Overview).

[LLMNR-NBT-NS-Poisoning-ATTACK](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-ATTACK)

Here I explore detecting a man in the middle LLMNR/NBT-NS Poisoning where the attacker to gains an NTLM hash for an account within the ARK.local domain.

I use Security Onion's ELK (Elasticsearch, Logstash, Kibana) stack to analyze network traffic off a phyisical managed switch with a SPAN/Mirror port to observe the attack.  

Link-Local Multicast Name Resolution and NBT-NS (NetBIOS Name Service) poisoning are attacks used to exploit weaknesses in name resolution protocols found in Windows machines. These protocols are used to identify hosts in the network when DNS doesn't work.

A victim will attempt to connect to a device, and fail. When it fails an LLMNR/NBT-NS broadcast is sent out asking who knows how to connect to the device.

The attacker will send malicious responses to LLMNR/NBT-NS queries. The attacker sends crafted responses to the target machine, pretending to be the device with the requested name. If the target machine accepts the spoofed response, it may use the attacker's IP address to communicate with the attacker instead of the legitimate one.

This results in the attacker capturing NTLM hashes of the account trying to connect to the requested device. With the hash, the attacker can either crack them, or relay those credentials to another machine in the network for lateral movement and privilege escalation. 

## Network Map
![V2-01222021-CYBER-INTERFACE-HD](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-ATTACK/assets/140366635/73938a13-2c11-4d82-8948-99050ec605ea)

**Note that in this exercise I temporarily had the victim workstation's IP set as 192.168.0.6 instead of 192.168.10.6 seen on the map above.**

## Detecting the Attack

In Security Onion, at a high level overview we can see all the types of connections between our Victim 192.168.0.6 and our attacker 192.168.10.99.

Depending on install settings for Security Onion, either Zeek or Suricata as the underlying network protocol analyzer in the background, categorized the network traffic seen with the conn, weird, and ntlm fields with only 16 logs observed:
![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/f2b58280-dfbc-4a1a-a7c2-1e802dacc207)


If you read my [LLMNR-NBT-NS-Poisoning-ATTACK](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-ATTACK), the only action the victim did was enter the attacker's IP in an attempt to connect to it as a share in the File Explorer window. 

## Security Onion Conn Dashboard 


