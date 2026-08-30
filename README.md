# NoMoreSACL
Enumerate User and Computer Objects via SAMR Protocol and Evade SACL Logging simultaneously



https://github.com/user-attachments/assets/39a6f67d-5720-4240-95d5-5d3417f12381


[Watch the High Quality video on YouTube](https://www.youtube.com/watch?v=fk0j3IpnUao)

I'd be glad to hear you'r thoughts and use you'r ideas, so i appreciate any contribute :)

**Note** : Due to the nature of AD architecture, the Primary DNS address on each client point to DC (Most of the Time the DC has DNS Role too), but if in you'r case it's different, feel free to change it 
**Note2** : I Also made the request to kerberos ssp/ap which is done via requesting with dns name not IP, if you prefer IP, it would result in ntlm request (msv1_0.dll)


https://github.com/user-attachments/assets/942453c2-8c41-4835-97a0-c1eeac6612a8


Also note that not every MS-SAMR Protocol is evasive


