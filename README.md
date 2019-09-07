## Dns Server
####Some sites over shecan.ir (sanction.list)
Some websites are not available in Iran. You should put it in `sanction.list` (Please check that shecan supports that website)  
####Some sites over google doh (what receives 10.10.34.XX in default response)
Some websites are blocked in Iran and default dns request receives 10.10.34.XX in response. So we can use DoH(dns over http) in this case 
####Default dns: 8.8.8.8, 8.8.4.4
Otherwise we use google dns
####Local dns server (local.list)
We can add some local dns records in `local.list`. This file is in JSON format.  
####Blacklist (blacklist.list)
If we want block some websites locally, we can add that website in `blacklist.list`