# 🔵 LLMNR-NBT-NS-Poisoning-DETECTION 🔵

This project is a sub-project to: 

[ESXi-Home-SOC-Lab-Network-Overview](https://github.com/gervguerrero/ESXi-Home-SOC-Lab-Network-Overview).

[LLMNR-NBT-NS-Poisoning-ATTACK](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-ATTACK)

Here I explore detecting a man in the middle LLMNR/NBT-NS Poisoning where the attacker to gains an NTLM hash for an account within the ARK.local domain.

I use Security Onion's ELK (Elasticsearch, Logstash, Kibana) stack to analyze network traffic off a phyisical managed switch with a SPAN/Mirror port.  

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
![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/de19ec91-1207-423a-9a5c-6e001a8f8a94)
![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/97f49f07-435a-4b5b-8832-06ed3db8db15)
![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/8d459fc1-5a84-415d-877d-0fb3cacd3644)

Above we can see the victim 192.168.0.6 connecting to the attacker 192.168.10.99 over SMB port 445, and generated 4 logs under a 1 second timespan.  

In the top picture we can a connection state of OTH and below a Connection History of SADR.

Using [Corelight's Zeek Log Cheatsheet](https://github.com/corelight/zeek-cheatsheets/blob/master/Corelight-Zeek-Cheatsheets-3.0.4.pdf), we can decipher these lettered codes for the connection.

![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/ea1b90dd-7ee1-421e-84a2-80982ce7ba7c)

![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/5a3d8389-07cf-4b8f-99f6-0d63ad65e8ed)





Connection State: OTH
- No SYN, not closed. Midstream traffic. Partial Connection.

Connection History: SADR
Orig Host is UPPERCASE, Responder is lowercase

- S: A SYN without the ACK bit Sst
- A: A pure ACK
- D: Packet with payload ("data")
- R: Packet with RST bit set

### Analyst Notes:
From a security analyst point of view, viewing this in the Conn dashboard is odd behavior.

Due to the lack of enterprise network assets in this small project, we aren't able to exactly baseline if other computers are doing the exact same thing to this "SMB Server" as we would in a real world scenario.  

Based on these following observations, we can make a conlusion that this is an anomaly that should be investigated or clarified.

1. The Client is making SMB connections to another computer in the network that is NOT specified as an SMB server.
   
2. A standard SMB connection between a Client and Server should follow the standard TCP 3 way handshake model before data is exchanged and service is provided. Why is it that only the Client sends sending data and the Server doesn't return any data? Observe the SADR and OTH connections and data sent in the dashboard.

3. The "SMB Server" did NOT reject the connection, it only accepted the data sent by the client and did not return any data. 

4. If this really is SMB activity, why weren't any SMB logs generated by zeek? Zeek looks at how a protocol behaves and catergorizes it based on it's actions and not it's port numbers or labels. If there was real SMB activity, an SMB log shown below would populate:

![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/d4c72fc7-294e-40c6-b9fe-e5b8737fb61d)
![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/b9e64449-0a8d-4c97-b8d9-3a77c5573a4b)

## Security Onion Weird Dashboard

Seen in the first Security onion picture shown above towards the start, zeek labeled some of the traffic seen between the attacker and the victim as "weird'.

Here we explore the logs tagged as weird in the Security Onion Weird Dashboard:

![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/121ba3d9-d44b-42d8-8d69-6bfb7fd0779b)
![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/30fb8b4f-8b51-44cc-8893-943e80d91d04)

This is one of the 8 logs expanded, giving some vague information:

![image](https://github.com/gervguerrero/LLMNR-NBT-NS-Poisoning-DETECTION/assets/140366635/effb2116-10a4-4929-ba24-bba3a7abf073)

### Analyst Notes:

The existence of weird logs alone is something that needs to be looked into. It doesn't immediately warrant a full investigation and mean that malicious activity is behind it, but it is usually requires attention to clarify the activity. Weird logs generated by zeek usually mean one of the following:

**Unusual Network Activity:**
- Events related to uncommon or non-standard network activities that could be indicative of suspicious behavior.

**Protocol Violations:**
- Detection of network protocols that are not being used according to their standard specifications.

**Unusual Traffic Patterns:** 
- Detection of traffic patterns that differ significantly from the typical behavior observed on the network.

**Potential Threat Indicators:** 
- Identification of potential threat indicators, such as suspicious URLs, malformed packets, or unexpected network connections.

**Excessive Connections:** 
- Detection of a large number of connections from a single source or to a single destination, which could be indicative of scanning or reconnaissance activities.



