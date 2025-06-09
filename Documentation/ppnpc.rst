
.. SPDX-License-Identifier: GPL-2.0
=============================================
Per-Process Network Packet Counting (PPNPC)
=============================================

Overview
========

The PPNPC module enables per-process network packet tracking by hooking into
Netfilter’s pre-routing and post-routing stages. It associates each packet
with its originating or receiving process using the socket ownership.

Motivation
==========

Tools like `netstat`, `ss`, or `nethogs` provide similar functionality in
userspace, but PPNPC allows for **low-overhead, real-time** tracking of
packet counts directly in kernel space. This is useful in:

- Forensics and malware analysis
- Network policy auditing per process
- Lightweight container traffic monitoring

Usage
=====

1. Load the module:

   # modprobe ppnpc

2. Read stats:

   $ cat /proc/ppnpc_stats

3. Unload:

   # rmmod ppnpc

Limitations
===========

- Only tracks IPv4 packets currently.
- Process PID association relies on `skb->sk` and may not work with all protocols.

