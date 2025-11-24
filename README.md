
# Generate a keypair

`$ kallisti keypair`

## Use /dev/random instead

`$ kallisti scalarmult < /dev/random`


# Establish peering

```bash
$ cp example-server.yaml config.yaml
$ nano config.yaml
$ sudo kallisti config.yaml
```

## Set point-to-point and a route, for example:

```bash
$ sudo ip addr add 10.42.42.2/32 peer 10.42.42.1 dev kallisti42
$ sudo ip route add 10.42.42.0/24 via 10.42.42.1
```

## Use 2 CPU cores

`$ sudo kallisti +RTS -N2 -RTS config.yaml`

## Setting TCPDROP variable for websocket-based peerings (experimental)

```bash
$ export TCPDROP=1024
$ sudo kallisti
```

This drops every 1024th TCP packet sent from your tun device.

Useful to prevent TCP meltdowns, stemming from the TCP-over-TCP problem:
The inner TCP retransmission timer is never increased,
resulting in exponential retransmissions in the inner TCP stack on packet loss,
which completely congest the inner TCP stack and impair the outer TCP stack.

The TCPDROP environment variable effectively flattens the bandwidth curve,
by distributing retransmissions evenly among all transmissions, that would have
otherwise occured during a TCP meltdown.

Lower this value, when you have bad connectivity.
Set this value to 0, when you have *perfect* connectivity.

# Protocols

Find a way to securely synchronize your system clock (for instance NTP)!

## Criteria

- authentication:   the playload is authenticated

- encryption:       the payload is encrypted

- forward secrecy:  the payload is encrypted using ephemeral keys

- efficiency:       the protocol is designed with maximum performance in mind

- asynchronicity:   after the initial handshake (if any) clock skews do not result in temporary DoS

- interoperability: the protocol plays nice with existing web standards like TCP, TLS, HTTP, etc.
                    and deals with real world limitations like web proxies, firewalls, etc.

## Comparison

- kallistn (experimental): authentication, encryption, asynchronicity, efficiency, forward secrecy

- kallistai (recommended): authentication, encryption, forward secrecy, efficiency

- nacltai:                 authentication, encryption, efficiency

- nacl0:                   asynchronicity, efficiency

- raw:                     efficiency, asynchronicity

- wsnacln (with TLS):      interoperability, authentication, encryption, asynchronicity, forward secrecy

- wsraw (with TLS):        interoperability, asynchronicity

- wsnacln:                 authentication, encryption, interoperability, asynchronicity, forward secrecy

- wsraw:                   interoperability, asynchronicity


Protocols running over websockets secure `wss://` do not gain additional security through TLS,
since no certificate validation takes place. An additional TLS layers might be interesting
in special cases of web proxies, that do not handle cleartext websockets well.

