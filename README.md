## Dns Server
This dns server tends to send responses in accordance to the received requests. It actually determines which DNS server to respond the requests with, by looking across the sites. What we have here is a proxy server in the middle. It handles either of the below functionalities.
### looking for proper DNS server
The DNS server could be among the following servers:
#### Shecan.ir (Sanctions list)
Some websites are not available in Iran. You should manually add it to the `sanction.list` file which is included in the repository (Please check if the website is supported by Shecan)
#### Google doh (in the case that default DNS server is used and the response is of 10.10.34.3X format)
Some websites are blocked in Iran and default dns requests receive 10.10.34.XX in response. So we can use DoH (dns over http) in this case
#### Default dns: 8.8.8.8, 8.8.4.4
Otherwise we can use google dns
#### Local dns server (local.list)
We can add some local dns records to the `local.list`. This file is in JSON format.
#### Blacklist (blacklist.list)
If we wish to block some websites locally, we can add that website to the `blacklist.list`