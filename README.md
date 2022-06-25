# bpfcountd

This daemon was created to obtain packet statistics in larger networks
without stressing the cpu resources. *bpfcountd* will count the amount of
packages and bytes over time (for each defined rule).  The rules are defined
using the tcpdump filter syntax ([bpf](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)).
The collected data is provided on unix socket in plaintext.


## Dependencies

* libpcap


## Supported Platforms

* Tested:
    * Arch Linux
    * Debian
* Should work without special regards:
    * Any systemd based Linux distro
* Should work after integration in init system:
    * Linux
* No support yet:
    * Any other platform with libpcap support
    * The ```get_mac(...)``` is not cross platorm yet


## Example

You can define multiple rules using the bpf syntax and assign an
identifier to each of them. The format is ```<identifier>;<bpf>```.
See example below:

**Filters**

```
arp-me;arp and ether src $MAC
icmp6;icmp6
arp-reply-gratious;ether broadcast and arp[6:2] == 2
```

The statistics are exported via unix socket. The path is configurable by a
command line parameter. The format of the output is ```<identifier>:<bytes>:<packetcount>```.

**Results**

```
arp-me:450:10
icmp6:100:4
arp-reply-gratious:120:30
```

**Kernel Prefilter**

To reduce the impact on unrelated traffic, a prefilter should be configured.
If set only packets matching the prefilter will be copied to userspace for
further examination by bpfcountd.

**Use with prometheus node_exporter:**

Add a crontab:
```
* * * * * ${pathtobpfcountddir}/dist/prometheus_txtfile.sh /var/run/bpfcountd.${interface}.sock > /var/run/bpfcountd.${interface}.txt
```

## HowTo

**Installation**

``` shell
$> # install the dependencies on debian
$> apt-get install libpcap-dev
$>
$> # install bpfcountd (all platforms)
$> git clone <url>
$> cd bpfcountd
$> make
$> sudo make install
$> cp dist/systemd@.service /lib/systemd/system/bpfcountd@.service
```

**Help**

``` shell
$> bpfcountd -h
bpfcountd -i <interface> [-F <prefilter-expr>] -f <filterfile>
          [-b <buffer-size>] [-u <unixpath>] [-h]

-F <prefilter-expr>   an optional prefilter BPF expression, installed in the kernel
-f <filterfile>       a the main file where each line contains an id and a bpf
                      filter, seperated by a semicolon
-b <buffer-size>      size of the capture buffer in bytes (default: 2*1024*1024)
-u <unixpath>         path to the unix info socket (default is ./test.sock)
```

**Configuration**

Create ```/usr/local/etc/bpfcountd/<interface>.filters```. Or you can take
one of the example files in ```/usr/local/etc/bpfcountd/``` first.

The format of the filter file:
```
<identifier1>;<bpf>
<identifier2>;<bpf>
```

You can use the ```$MAC``` placeholder in your bpf and it will be
replaced by the mac address of the interface at runtime.

**Results**

I recommend openbsd-netcat to read the unix socket from your shell.

``` shell
$> nc -U <unixpath>
```

## systemd integration

**Start**

``` shell
$> systemctl start bpfcountd@<interface>
```

**Enable**

``` shell
$> systemctl enable bpfcountd@<interface>
```

**Unix socket path**

```
/var/run/bpfcountd.<interface>.sock
```
