# multiwand

A daemon that detects the routing table entries that have gateways configured, and regularly pings
them to ensure they are reachable. If/when tehy are not, it temporarily increases the metric for
that routing table entry, until the gateway resumes responding to pings.

Thus linux will prefer to route network traffic to other default routes, instead of the one that
is currently down.

On Debian-derived distributions (Ubuntu et al) add a 'metric' line to the interface(s) in
`/etc/netowrk/interfaces` that can reach the internet. Use a lower number for the interface
you'd prefer linux to use.

It's OK to have more than one default route, provided they have different metric values.

*Note:* This demon currently only handles automatic failover when a gateway fails. It
doesn't (yet) attempt to support load-balancing, a much trickier challenge.

## Dependencies

* libnl-route-3
  * package libnl-route-3-dev is required to build
* liboping0 
  * package liboping-dev is required to build
