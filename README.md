# bpfcountd

You can define some bpf (berkley packet filters) for your interfaces and *bpfcountd*
will count the amount of packages and the total bytes for each single filter for you.
The [bpf](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) are also known as
tcpdump filter syntax. This daemon was created to monitor the broadcast traffic
in a large layer2 network like the freifunk batman-adv mesh.


## Dependencies

* libpcap


## Example

You can define multiple bpf and assign an identifier to each of them.

**Filters**

```
arp-me;arp and ether src $MAC
icmp6;icmp6
arp-reply-gratious;ether broadcast and arp[6:2] == 2
```

The statistics are exported via unix socket. The path is configurable by a
command line parameter. (I recomment openbsd-netcat to read the unix socket
from your shell.) The format is ```<identifier>:<bytes>:<packetcount>```.

**Results**

```
arp-me:450:10
icmp6:100:4
arp-reply-gratious:120:30
```


## HowTo

**Installation**

``` shell
$> apt-get install libpcap-dev netcat-openbsd
$> git clone <url>
$> cd bpfcountd
$> make
$> sudo make install
```

**Help**

``` shell
$> bpfcountd -h
bpfcountd -i <interface> -f <filterfile> [-u <unixpath>] [-h]

-f <filterfile>       a the main file where each line contains an id and a bpf
                      filter, seperated by a semicolon
-u <unixpath>         path to the unix info socket (default is ./test.sock)
```


**Configuration**

Create ```/usr/local/etc/bpfcountd/<interface>.filters```. (Maybe you can simply take
one of the example files in ```/usr/local/etc/bpfcountd/``` first.)

The format is:
```
<identifier>;<bpf>
<identifier>;<bpf>
```

You can use the ```$MAC``` token in your bpf and it will be replaces by the mac address
of the interface at runtime.

**Start**

``` shell
$> systemctl start bpfcountd@<interface>
```

**Enable**

``` shell
$> systemctl enable bpfcountd@<interface>
```

**Results**

``` shell
$> nc -U /var/run/bpfcountd.<interface>.sock
```
