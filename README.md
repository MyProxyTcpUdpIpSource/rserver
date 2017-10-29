# NAME
`rserver` or whatever you like ... you can name it.

# SYNOPSIS

 * In client mode
 
	 `./rserver -AsClient -Address :1080 -Password="Im-Having-An-Existential-Crisis" -RemoteServer=1.2.3.4:5000 # You can add multiple servers when you write config file`
	
 * In server mode
 
	 `./rserver -AsServer -Address=:5000  -Password="Im-Having-An-Existential-Crisis"`
	 
 Currently supported encryption methods are aes-128-cfb, aes-192-cfb and aes-256-cfb.
 
# DESCRIPTION
`rserver` is a network relay server that can handle TCP connections and could bypass a firewall. `rserver` follows SOCKS5 protocol and thus, you can work with `rserver` using commands such as `curl`:
`curl --socks5 127.0.0.1:1080 google.com -vvv -L` Of course, you can also put SOCKS5 address into browsers.
Before you run any command, first you need to let client and remote server run. In remote you run `rserver` in server mode: `./rserver -AsServer -Address :5000 -Password this-is-password` and in local you run `rserver` in client mode: `./rserver -AsClient -Address 127.0.0.1:1080 -Password this-is-password -RemoteSever myserver.net:5000`.

# BUILD
 `go get github.com/luSunn/rserver` and then you do `make` or `go build`

# Load from config file


``` bash

$ cat client.json
# local
{
   	"address": "127.0.0.1:1080",
    "isclient": true,
    "logfile": "/var/log/rserver.log",
	"method": "aes-192-cfb",
	"password": "I'm-having-a-wonderful-day-so-far",
	"servers": [
	"myserver1:8080",
	"myserver2:9000",
	"myserver3:7979"	
	],
}

$ ./rserver -C client.json

# remote
$ cat remote.json 
	
{
	"address": ":8080",
	"isserver": true,
	"log": "/var/log/rserver.log",
	"method": "aes-192-cfb",
	"password": "I'm-having-a-wonderful-day-so-far",
}
	
$ ./rserver -C client.json


```

# HOW THIS WORKS?
`rserver` works pretty much simple. According to [rfc1928](https://tools.ietf.org/html/rfc1928), SOCKS5 servers should accept username and password based authentication from clients but since `rserver` can only talk between clients and remote servers, it is no longer necessary to implement that authentication. When clients get requests from users, clients soon encrypt SOCSK5's header and send it to a remote server and then remote server connects to a target and sends data back to clients. Header's first two bytes are reserved for the data length.

# KNOWN SOCKS5 CLIENTS

    
	
	#assuming rserver is running in client mode at port :1080...
	$ ssh -l xun -p5000 -o ProxyCommand='nc -x localhost:1080 %h %p' server.net # this is useful when the network has aggressive port filterings.
	
	$ google-chrome proxy-server=socks://127.0.0.1:1080 # open Chrome browser with a proxy
	
	$ dropbox proxy manual socks5 127.0.0.1 1080  # configure dropbox with socks5
	
# TODO
 * Support UDP relay
 * Support UDP associate command.
 * Wrap whole connection with proper encryption method so that we can perfectly bypass firewall.
 * custom DNS options: I want to use google's 8.8.8.8 or 8.8.4.4 dns server instead of defualt dns.
