## Summary

* Name: t2na_counter_true_egress_accounting
* P4 version: P4_16
* Architectures: Tofino2 Native Architecture (T2NA)
* Programming stack: Barefoot Runtime Interface (BRI)

By default, counter or meter at egress uses the computed packet length for the
ingress pipeline. This means that the counter or meter is unaware of the final
packet size and will not reflect the real output packets on the wire. When true
egress accounting is enabled on the counter or meter constructor, the final
byte count from egress deparser after the final output packet has been
re-assembled will be used instead. The example program consists of a lookup
table that matches for src MAC address and truncates the packet.  Therefore,
the true egress accounting feature is required to get the true packet byte
count.
