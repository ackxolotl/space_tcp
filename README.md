# S3TP

A new implementation of a simple stupid satellite transport protocol. To be
continued ...

## Build instructions

Check out the repository and its submodules:

```
git clone https://github.com/ackxolotl/space_tcp.git
cd space_tcp/
git submodule init
git submodule update
```

### Linux

Install the following dependencies:

* gcc or clang
* cmake
* make

Run these commands to build the library, example applications, tests and
documentation:

```
mkdir build
cd build/
cmake ..
make
```

## Documentation

Doxygen documentation can be found in `build/doc/html/index.html`.

## Usage

There are two example applications included for Linux, a packet sender and a
packet receiver.

Since the examples create TUN network interfaces for communication they have to
be run with root permissions. Alternatively, the `CAP_NET_ADMIN` capability can
be set on the executables (in the build directory):

```
sudo setcap cap_net_admin=eip ./examples/linux/receiver
sudo setcap cap_net_admin=eip ./examples/linux/sender
```

Note that the above approach does not work in `/tmp/`.  With the network
capability, the applications can be run without `sudo`:

```
./examples/linux/receiver
./examples/linux/sender
```

Once the applications have been started, set up the TUN devices for traffic
forwarding. First, enable IPv4 packet forwarding on the host:

```
sudo sysctl -w net.ipv4.conf.all.forwarding=1
```

Run both applications, the `receiver` and the `sender`. While the applications
are running, set IPv4 addresses on the TUN interfaces:

```
sudo ip addr add 10.1.2.1/24 dev tun0
sudo ip addr add 10.9.8.1/24 dev tun1
```

Now enable forwarding between the two interfaces:

```
sudo iptables -A FORWARD -i tun0 -o tun1 -j ACCEPT
sudo iptables -A FORWARD -i tun1 -o tun0 -j ACCEPT
```

The `receiver` should now receive packets from the `sender`. Do not forget to
disable any firewalls on your host!

If packet forwarding does not work, check if the TUN interfaces are down. If so
run:

```
sudo ip link set tun0 up
sudo ip link set tun1 up
```

## Traffic monitoring with Wireshark

Run Wireshark on `tun0` or `tun1` to analyse the S3TP packets.

To get protocol information about S3TP in Wireshark, we have included a protocol
dissector written in Lua. Run these commands to install the dissector:

```
mkdir -p ~/.local/lib/wireshark/plugins/
cp ws_s3tp_dissector.lua ~/.local/lib/wireshark/plugins/
```

Restart Wireshark.

## Tests

There are more than 50 GoogleTest test cases included in S3TP.

To run the test cases, change into the build directory and execute `make test`.

