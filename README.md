# Project 3 - Subnetting and Forwarding

- Name: Troy Berhow
- Email: troyberhow@u.boisestate.edu
- Class: CS525/ECE334-001

## Known Bugs or Issues

There are no know issues or bugs

## Experience

TODO: Describe your experience with the project (struggles, breakthroughs, etc.).

## Design

IPv4 addresses are stored as 32-bit integers, and each CIDR block stores an
address and a prefix length. The subnet mask is formed from the leading
`prefix` one-bits. The `/0` case is handled separately and produces an all-zero
mask, avoiding a 32-bit shift; this makes `0.0.0.0/0` contain every address.
For `/32`, the mask is all ones, so the block contains exactly its one
specified address.

Host-address calculations follow the conventional network and broadcast
exclusions for prefixes `/0` through `/30`: the first and last host are the
network address plus one and broadcast address minus one, respectively, and
the host count is `2^(32 - prefix) - 2`. The `/0` count uses a 64-bit result
because `2^32` does not fit in 32 bits. `/31` is treated as a two-address
point-to-point block, so both addresses are usable rather than reserving
network and broadcast addresses. A `/32` is a single-address block, with that
address as its one usable host.

The forwarding table holds routes in a dynamically grown array and rejects
duplicate destination blocks. Lookup scans every route, uses the route's mask
to test whether it contains the destination, and keeps the match with the
greatest prefix length. Thus, more-specific routes win regardless of insertion
order; a `/0` default route is used only if no more-specific route matches.
Table-file entries must name a network address (host bits all zero), and
`default` is accepted as shorthand for `0.0.0.0/0`.

## Analysis

TODO: Provide your analysis of the results. If the assignment does not require
analysis, you can remove this section.

Here is an example of how to include a plot in your README:

![Example Image](scripts/example_plot.png)
