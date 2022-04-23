# Telnet-Sniffer

C code for sniffing out TELNET login information.
In order to use this attack a "man in the middle" must be performed with the victim.
Read more about man in the middle attack [here](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
            
## How To Run
1. download or clone this repository.
2. Change the [NIC define in line 11]https://github.com/eladsez/Telnet-Sniffer/blob/main/telnetSniffer.c#:~:text=%23define%20NIC-,%22wlp0s20f3%22,-int%20captureTelnet%20%3D%200 to the Network Interface Controller you wish to sniff from.
3. open a terminal in the main folder and run the following command:  

```
gcc telnetSniffer.c -o telSniff -lpcap
```  
4. to run use the following comand:  

```
./telSniff
```    

## DISCLAIMER!
This is only for testing purposes and can only be used where strict consent has been given.  
Do not use this for illegal purposes, period. 
