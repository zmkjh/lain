# Feasibility of Infrastructure-Free Direct P2P Communication Across Chinese ISPs: A Coverage Analysis Under Heterogeneous NAT and IPv6 Constraints

**Authors:** zmkjh

**Affiliation:** njfu

**Date:** May 2026

---

## Abstract

The feasibility of infrastructure-free peer-to-peer (P2P) communication — without relay servers, fixed public-IP infrastructure nodes, or DHT supernodes — remains a critical yet underexplored problem in network stack design. This paper presents the first systematic coverage analysis of direct P2P connectivity across China's three major Internet Service Providers (ISPs): China Mobile, China Telecom, and China Unicom. We develop a theoretical model that decomposes the connectivity problem into an IPv4 NAT-compatibility layer and an IPv6 reachability layer, accounting for asymmetric initiation strategies that require only one peer to have inbound IPv6. Using the latest empirical data on NAT types (Cone, ADF Symmetric, APDF Symmetric) and IPv6 deployment rates (8.69 billion active users, 77% penetration as of December 2025), we construct a 7×7 ISP-NAT category matrix and derive a total direct connectivity probability of **98.35%** for random user pairs and **~99.7%** for technical early-adopter users. The remaining <2% gap is attributable to APDF Symmetric NAT pairs lacking IPv6, representing a mathematically provable hard boundary for direct connection — resolvable only through user-side IPv6 configuration or multi-hop overlay fallback. We provide rigorous proofs for each NAT-pair compatibility decision and discuss the implications for next-generation P2P library design.

**Keywords:** NAT traversal, P2P, IPv6, UDP hole punching, APDF, Symmetric NAT, China ISP, direct connectivity

---

## 1. Introduction

Peer-to-peer (P2P) communication allows devices to exchange data directly without centralized servers. In the idealized Internet model, any two devices with global IP addresses can communicate directly. In practice, Network Address Translation (NAT) devices, Carrier-Grade NAT (CGNAT), and stateful firewalls create significant barriers to direct connectivity.

China presents a uniquely challenging yet illustrative environment for P2P connectivity analysis. With approximately 1.1 billion Internet users across three major ISPs, the country exhibits a heterogeneous mixture of NAT implementations (Cone, Address-Dependent Filtering Symmetric, and Address+Port-Dependent Filtering Symmetric) and varying levels of IPv6 deployment maturity. China also leads the world in IPv6 absolute deployment: as of September 2025, 865 million active IPv6 users accounted for 77% of all Chinese Internet users, with mobile network IPv6 traffic reaching 69% of total mobile traffic [1, 2].

This paper investigates a specific question that, to the best of our knowledge, has not been systematically answered in the literature: **Given the heterogeneous NAT environments of Chinese ISPs and the constrained toolkit consisting only of STUN-based hole punching, port prediction, Birthday Attack, TCP Simultaneous Open, and IPv6 direct connection (with no relay servers, no DHT supernodes, and no fixed public-IP infrastructure), what percentage of arbitrary device pairs can achieve direct two-way communication?**

We address this question through three contributions:

1. **ISP-NAT classification**: We synthesize the latest community measurement data to classify each major Chinese ISP's broadband and cellular network into one of three NAT types: Cone (Endpoint-Independent Mapping), ADF Symmetric (Endpoint-Dependent Mapping with Address-Dependent Filtering), or APDF Symmetric (Endpoint-Dependent Mapping with Address+Port-Dependent Filtering).

2. **Rigorous compatibility matrix**: We prove, for each possible NAT-type pair, whether direct IPv4 connectivity is theoretically possible using state-of-the-art traversal techniques.

3. **Combined coverage model**: We model the joint probability of connectivity, incorporating both IPv4 NAT compatibility and IPv6 asymmetric reachability, and calculate the total addressable fraction of the Chinese Internet population.

### 1.1 Prior Work

UDP hole punching was first formalized by Ford et al. [3], who demonstrated that direct P2P connections were possible through a wide range of consumer NAT devices. Guha and Francis [4] later provided the first large-scale empirical characterization of NAT behavior. RFC 4787 [5] and RFC 5382 [6] standardized NAT behavioral requirements, recommending Endpoint-Independent Mapping (EIM) and Endpoint-Independent Filtering (EIF) as best practices. However, many CGNAT deployments in practice employ Endpoint-Dependent Mapping (EDM), commonly known as Symmetric NAT.

Tailscale's Birthday Attack paper [7] described a probabilistic approach to traversing one-sided Symmetric NATs using K×K probe pairs (256×256 yielding ~64% success probability). libp2p's DCUtR specification [8] reported ~70% overall hole punch success in production across 4.4 million measurements.

To our knowledge, no prior work has combined ISP-level NAT classification with IPv6 deployment data to compute holistic P2P coverage for a specific national Internet environment.

---

## 2. Background and Definitions

### 2.1 NAT Classification

Following RFC 4787, we classify NATs along two independent dimensions:

**Mapping behavior** (how the NAT assigns external ports):
- **Endpoint-Independent Mapping (EIM)**: The same external port is reused for all destinations (Cone NATs).
- **Endpoint-Dependent Mapping (EDM)**: A different external port is assigned for each unique destination (Symmetric NATs).

**Filtering behavior** (what inbound traffic the NAT allows):
- **Endpoint-Independent Filtering (EIF)**: Any external host can send to the mapped port.
- **Address-Dependent Filtering (ADF)**: Only hosts whose IP address matches a previously-contacted destination can send.
- **Address and Port-Dependent Filtering (APDF)**: Only hosts whose IP and port match a previously-contacted destination can send.

We use the following three-category classification for this paper:

| Notation | Name | Mapping | Filtering |
|----------|------|---------|-----------|
| C | Cone | EIM | EIF or ADF or APDF |
| S_ADF | ADF Symmetric | EDM | ADF |
| S_APDF | APDF Symmetric | EDM | APDF |

The distinction between S_ADF and S_APDF is critical: both are "Symmetric" in the traditional taxonomy, but their traversal properties differ fundamentally.

### 2.2 Traversal Technique Taxonomy

We consider the following allowed techniques:

1. **STUN-based UDP hole punch** [9]: Both peers contact a STUN server to discover their external addresses. Via an out-of-band signaling channel (invite channel), they exchange addresses and send UDP probes simultaneously to each other. Creates bidirectional NAT state entries allowing subsequent communication.

2. **TCP Simultaneous Open (TSO) with wide time window**: Both peers send TCP SYN packets to each other simultaneously. The SYNs establish stateful NAT entries that allow the TCP three-way handshake to complete bidirectionally. A "wide" time window (seconds rather than milliseconds) is used to avoid timing sensitivity.

3. **Birthday Attack with relay-mediated coordination**: Peers open K sockets each (K typically 16-256), discover their mapped ports via STUN, and exchange the full port list via a pre-established relay connection (which serves only as a signaling channel). Each peer then sends probes from all K sockets to all K addresses of the other peer. Without relay coordination, the Birthday Attack is limited to a single-round attempt using the port set included in the initial invite code.

4. **IPv6 direct connection**: One peer acts as client (initiator) and the other as server (listener), using globally routable IPv6 addresses. Stateful firewalls, when present, are modeled as ADF (IP-only filtering), enabling connectivity as long as at least one peer's network allows inbound IPv6.

**Explicitly excluded** are: TURN relays, multi-hop overlay forwarding, DHT supernodes with fixed public IPv4 addresses, and any dedicated infrastructure servers beyond external STUN endpoints. Note: relay-mediated Birthday Attack coordination (using a peer-to-peer relay node within the overlay network, not a dedicated server) is included as it constitutes a signaling-only use of an existing P2P connection rather than infrastructure dependency.

### 2.3 Assumptions and Scope Boundaries

Our analysis is built on the following explicit assumptions:

**A1 (STUN Availability)**: Externally accessible STUN servers exist and are reachable by both peers. We assume neither the STUN protocol nor the specific servers are blocked by ISPs. In the Chinese context, we prioritize domestically-hosted STUN servers (miwifi.com, qq.com) to mitigate GFW-related interference.

**A2 (Out-of-Band Signaling)**: An initial signaling channel (referred to as the "invite channel") exists between the two peers, allowing them to exchange a one-time message containing their discovered addresses, capability declarations, and port hints. This channel is assumed available at the start of the connection attempt but is not required to persist beyond the initial exchange. In practice, this corresponds to a user-shared invite code via instant messaging, QR code, or `lain://` URI.

**A3 (UDP Reachability)**: Unless explicitly stated otherwise (e.g., Step 5 WebSocket fallback), UDP traffic between peers can traverse their respective ISP networks. We do not model ISP-level UDP blocking within China's domestic network, as such blocking between domestic ISPs is rare.

**A4 (Homogeneous ISP Classification)**: Peers are classified into discrete categories based on their ISP and access type. Intra-category NAT behavior is assumed homogeneous. Real-world variation within a category (e.g., regional differences in Unicom's CGNAT policy) is discussed in §7.4 Limitations.

**A5 (Independence)**: IPv6 reachability and IPv4 NAT type are treated as independent random variables. This is reasonable since IPv6 deployment and IPv4 CGNAT policy are managed by separate teams within ISPs and evolve on different timelines.

**A6 (Traversal Technique Competence)**: The P2P stack correctly implements all allowed traversal techniques, including proper use of unconnected UDP sockets (required for asymmetric routing in Cone × S_APDF traversal) and STUN CHANGE-REQUEST for NAT behavior characterization.

---

## 3. Chinese ISP NAT and IPv6 Landscape

### 3.1 Data Sources

Our ISP classification draws on multiple data sources:

- National IPv6 Development Monitoring Platform official statistics (as of Q3-Q4 2025) [1, 2]
- APNIC Labs AS-level IPv6 capability data [10]
- IPv6-test.com crowdsourced measurements [11]
- V2EX community reports on IPv6 inbound reachability [12]
- CSDN WebRTC STUN penetration test results [13]
- Third-party STUN-based NAT classification tool results [14]

Table 1 summarizes the classification for each ISP network type.

**Table 1: Chinese ISP NAT and IPv6 Classification**

| Category | Users (est.) | IPv4 Mapping | IPv4 Filtering | IPv6 Available? | IPv6 Inbound Reachable? |
|----------|-------------|-------------|---------------|-----------------|------------------------|
| A: CM Broadband | ~329M | EDM (Symmetric) | **APDF** (NAT4) | Yes | 80% (CPE FW configurable) |
| B: CM 4G/5G | ~250M | EDM (Symmetric) | **ADF** | Yes | 30% (core network blocks; inter-op partially works) |
| C: Telecom Broadband | ~200M | EIM (Cone) | APDF/EIF | Yes | 95% |
| D: Telecom 4G/5G | ~150M | EIM (Restricted Cone) | APDF | Yes | 90% |
| E: Unicom Broadband | ~120M | Mixed Cone/EDM | Mixed | Yes | 70% (regional variation) |
| F: Unicom 4G/5G | ~100M | EDM (Symmetric) | Mixed | Yes | 30% (5G SA blocks; inter-op partially works) |
| G: Other / Edge | ~200M | Mostly Cone | EIF/ADF | Varies | 60% |

### 3.2 Key Observations

**China Mobile Broadband (Category A)** is the only category with strict APDF filtering in production. Henan province fully transitioned to NAT4 in 2023, and this has become representative of China Mobile's national broadband policy [14]. The STUN-binding test confirms Symmetric NAT with port-dependent filtering: `pystun3 -H stun.qq.com` yields "NAT Type: Symmetric NAT."

**China Mobile 4G/5G (Category B)**, in contrast, uses ADF filtering rather than APDF. This is evidenced by WebRTC STUN penetration tests showing that "Mobile 4G to WiFi, Mobile 4G to Unicom 4G, Mobile 4G to Telecom 4G were all able to connect" [13]. If APDF were active, these connections would fail. The difference arises because mobile CGNAT pools use a shared address model (5-tuple-based session tracking) rather than the per-user fixed port allocation model used in broadband CGNAT [15].

**China Telecom** (Categories C, D) consistently provides Cone NAT on both broadband and cellular networks. IPv6 inbound is widely available. This makes Telecom the "easiest" ISP for P2P connectivity.

**China Unicom** (Categories E, F) exhibits the most variation. Broadband varies by province; some regions deploy Cone NAT while others use Symmetric. 5G SA networks block IPv6 inbound connections at the core network (UPF) level, similar to China Mobile's cellular behavior.

**IPv6 deployment**: As of Q3 2025, China had 865 million active IPv6 users (77% of all Internet users), with mobile network IPv6 traffic at 69% and fixed network IPv6 traffic at 31% [2]. However, independent measurements by APNIC and Cloudflare place China's actual end-to-end IPv6 traffic at approximately 34-38% [16], indicating a gap between network capability and application-level usage.

### 3.3 Edge Case Analysis

Beyond the mainstream categories, several boundary conditions affect real-world coverage.

#### 3.3.1 CGNAT Multi-IP Pool Effects

Large-scale CGNAT deployments (particularly China Mobile and China Unicom cellular) commonly employ multiple public IPv4 addresses in a pool. A single subscriber's traffic may exit through different public IPs depending on load balancing. This has two implications:

1. **STUN consistency**: A peer performing two consecutive STUN queries may receive different mapped IP addresses, causing our EDM detection heuristic to report "Symmetric" when the NAT is actually Cone (EIM) but behind a multi-IP pool. This can cause **false positive Symmetric classification**, understating achievable connectivity.
2. **Hole punch reliability**: Once a UDP flow is established through one pool IP, the CGNAT typically maintains affinity for that flow. Subsequent packets on the same 5-tuple continue through the same IP.

Mitigation: Additional STUN queries (3-5) to probe the extent of IP variation. If all ports are consistent per IP but IP varies, classify as EIM + multi-IP rather than EDM. This is reflected in our updated STUN methodology in the companion design document.

#### 3.3.2 Enterprise and Campus Firewalls

Corporate and university networks introduce additional filtering layers beyond ISP NAT:
- **Deep Packet Inspection (DPI)**: May block UDP entirely, forcing TCP-only paths
- **Stateful IPv6 firewalls**: Often configured to block inbound IPv6 by default
- **Application-layer filtering**: HTTP/HTTPS-only policies that block non-standard ports

Users in such environments appear in our model in Category G (Other/Edge), where we conservatively estimate 60% IPv6 inbound reachability. In practice, enterprise networks are the primary drivers of the WebSocket fallback requirement (Step 5 of the traversal chain).

#### 3.3.3 Mobile Network Specific Concerns

Cellular networks introduce unique failure modes not captured by NAT-type classification alone:

| Concern | Impact | Mitigation |
|---------|--------|------------|
| CGNAT session timeout (30-120s) | QUIC idle timeout may cause connection loss before keep-alive fires | Adaptive keep-alive based on observed timeout |
| Inter-operator IPv6 routing | IPv6 paths between different mobile carriers may be asymmetric or blocked | IPv4 fallback within traversal chain |
| Radio state transitions (RRC) | Dormant → Active transition adds 50-200ms latency spike | QUIC 0-RTT not applicable (new connection); connection migration may help |
| 5G SA IPv6-only networks | Some 5G SA deployments are IPv6-only with NAT64 for IPv4; STUN may not work for IPv4 | Direct IPv6 path becomes the only option |

#### 3.3.4 Dual-Stack Host NAT Variation

A single device on a dual-stack network may exhibit different NAT behavior on IPv4 vs IPv6. For example, a CM Broadband user may have:
- IPv4: S_APDF (strict CGNAT)
- IPv6: Cone-equivalent (stateful firewall with EIF behavior after first outbound packet)

Our model treats IPv4 and IPv6 reachability independently, which correctly captures this dual-behavior scenario.

#### 3.3.5 The "Birthday Attack × APDF" Question

A natural question is whether the Birthday Attack technique (K×K probe matrix, §2.2 item 3) can penetrate S_APDF filtering. Our Lemma 4 proof already establishes that it cannot: for any probe pair (i, j), the source port P_A_j (from A's K-th socket targeting B's i-th address) differs from P_A_stun (the port A advertised), and B's APDF filter requires an exact port match against the previously-advertised destination. The simultaneous opening of K sockets on each side creates K² probe pairs, but none meet the filter criteria because the filter predicate is not probabilistic—it is an exact-match comparison against a value that neither peer correctly predicts.

Note: This does not preclude the theoretical possibility of a "supervised Birthday Attack" where a relay node that is reachable by both peers actively coordinates port selection to match filter expectations. This scenario falls outside our "infrastructure-free" scope but represents interesting future work.

---

## 4. IPv4 NAT Compatibility Analysis

### 4.1 Lemma 1: Cone × Cone — Always Compatible

**Proof.** Let the Cone peer have external address (IP_C, P_C) as discovered via STUN. Let the other Cone peer have external address (IP_C', P_C'). Both peers send UDP probes to each other's discovered addresses. Since both NATs use endpoint-independent mapping, the same external port serves all destinations. The first probe from each side creates a NAT state entry. Subsequent packets match the state entries and are forwarded. Filtering behavior (EIF, ADF, or APDF on either side) does not affect the outcome because:
- With EIF: no filtering, all incoming packets accepted.
- With ADF: the incoming source IP matches the destination IP of the outgoing probe (the same IP was contacted by the peer's probe).
- With APDF: the incoming source (IP, port) matches the destination (IP, port) of the outgoing probe — by construction, both peers sent to the exact address the other peer's probe arrives from.

Thus, Cone × Cone is always compatible. ∎

### 4.2 Lemma 2: Cone × S_APDF — Always Compatible

**Proof.** Let C denote the Cone peer and A denote the S_APDF peer.

1. C uses STUN to discover (IP_C, P_C).
2. A uses STUN to discover (IP_A, P_A_stun), valid only for traffic to the STUN server.
3. Via the invite channel, C and A exchange addresses.
4. C sends a UDP probe from P_C to (IP_A, P_A_stun). C's Cone NAT maps this to (IP_C, P_C) — same port for all destinations.
5. A sends a UDP probe to (IP_C, P_C). A's Symmetric NAT (EDM) creates a new mapping (IP_A, P_A_C) for destination (IP_C, P_C), distinct from P_A_stun.

**At A's NAT:** The incoming probe from C arrives at P_A_stun, not P_A_C. Filtering check: P_A_stun was created for communication with the STUN server at (IP_STUN, 3478). The incoming source is (IP_C, P_C). Since IP_C ≠ IP_STUN, and APDF requires BOTH IP and port to match the previously-contacted destination, this packet is **DROPPED**.

**At C's NAT:** The incoming probe from A arrives at P_C from source (IP_A, P_A_C). C's Cone NAT either has no filtering (EIF) or checks IP only (ADF). In both cases, the packet is forwarded because filter check (when present) only cares about IP_A. The application at C receives the packet from (IP_A, P_A_C).

**Resolution via asymmetric routing**: The hole punch "succeeds" because C now knows A's actual source address (IP_A, P_A_C) and can respond to it. C sends a response to (IP_A, P_A_C). At A's NAT, this incoming packet has source (IP_C, P_C) targeting P_A_C. A's NAT has previously created a state entry for A's outgoing probe to (IP_C, P_C). Filtering check: source (IP_C, P_C) matches the destination (IP_C, P_C) of the outgoing probe. Exact match → **FORWARDED**. Bidirectional communication is now established through the (IP_C, P_C) ↔ (IP_A, P_A_C) channel.

This asymmetric mechanism works with C as the Cone side. A symmetric probe from A (simultaneously) is not required for success; C's first probe "leaked through" A's APDF filtering indirectly by revealing C's source address, which A can then target.

However, note the limitation: C must NOT use a connected UDP socket (which rejects packets from non-matching source addresses). An unconnected socket with recvfrom() is required.

Thus, Cone × S_APDF is compatible. ∎

### 4.3 Lemma 3: S_ADF × S_ADF — Compatible

**Proof.** Let A and B be two S_ADF (ADF Symmetric) peers.

1. A discovers (IP_A, P_A_stun) and B discovers (IP_B, P_B_stun) via STUN.
2. Via invite, they exchange these addresses.
3. A sends probe to (IP_B, P_B_stun). EDM mapping creates new source (IP_A, P_A_B) for destination (IP_B, P_B_stun).
4. B sends probe to (IP_A, P_A_stun). EDM mapping creates new source (IP_B, P_B_A) for destination (IP_A, P_A_stun).

**At A's NAT:** Receives from (IP_B, P_B_A) to P_A_stun. A's STUN state for P_A_stun: destination (IP_STUN, 3478). ADF filter checks: source IP_B vs STUN_IP ≠ match → **DROPPED** at the STUN state.

But A also has a second state entry: the outgoing probe from A to (IP_B, P_B_stun) created state with destination (IP_B, P_B_stun). The NAT allocated P_A_B for this. The incoming probe from B arrives at P_A_stun (not P_A_B), so the state entry for A→B doesn't help.

**The resolution**: In practice, A opens K sockets and sends to all K of B's ports. One of these will land on P_B_A (B's actual mapped port for talking to A). The application at A uses an unconnected socket.

More fundamentally, the ADF check only requires matching the source IP (not port). If A sent any probe to IP_B (regardless of port), the filter state allows all packets from IP_B (any port) through to any of A's mapped ports for which a corresponding state exists.

After the simultaneous exchange:
- A's NAT state for its probe to (IP_B, P_B_stun): destination IP_B (port irrelevant for ADF). Incoming from (IP_B, _any_) matches this IP → forwarded to A's internal socket.
- Similarly, B's NAT accepts from IP_A on any port.

Thus, after the simultaneous probe exchange, bidirectional communication flows through A's and B's actual mapped channels. Since ADF only checks IP (not port), the exact port mapping becomes irrelevant — as long as both sides have a state entry with the other's IP, all port combinations work.

Thus, S_ADF × S_ADF is compatible. ∎

### 4.4 Lemma 4: S_APDF × S_APDF — Incompatible

**Proof.** This is the hard boundary case. Let A and B be two S_APDF (APDF Symmetric) peers.

1. A uses STUN → (IP_A, P_A_stun). Valid only for STUN server.
2. B uses STUN → (IP_B, P_B_stun). Valid only for STUN server.
3. Via invite, exchange.

4. A sends probe to (IP_B, P_B_stun). EDM → new source (IP_A, P_A_B). Packet: (IP_A, P_A_B) → (IP_B, P_B_stun).

5. B sends probe to (IP_A, P_A_stun). EDM → new source (IP_B, P_B_A). Packet: (IP_B, P_B_A) → (IP_A, P_A_stun).

**At B's NAT**: Two possible states exist:
- State for B↔STUN: destination (IP_STUN, 3478). Incoming from (IP_A, P_A_B). Filter: (IP_A, P_A_B) ≠ (IP_STUN, 3478) → **DROP**.
- State for B→A: destination (IP_A, P_A_stun). Incoming from (IP_A, P_A_B). Filter: source port P_A_B ≠ destination port P_A_stun. APDF requires exact port match → **DROP**.

**At A's NAT**: Symmetrically:
- State for A↔STUN: (IP_STUN, 3478) with incoming (IP_B, P_B_A) → **DROP**.
- State for A→B: (IP_B, P_B_stun) with incoming (IP_B, P_B_A). P_B_A ≠ P_B_stun → **DROP**.

Neither side can receive the other's probe. The fundamental barrier is the conjunction of EDM (which causes source ports to change per destination) and APDF (which requires exact source port matching). Even with K×K probes (Birthday Attack), no probe pair can match because for any probe pair (i, j), P_A_j ≠ P_A_stun and P_B_i ≠ P_B_stun, meaning the filter check always fails.

TCP Simultaneous Open does not help, as it only widens the timing window without addressing the port-matching problem.

Thus, S_APDF × S_APDF is provably incompatible for direct connection. ∎

### 4.5 Lemma 5: S_APDF × S_ADF — Incompatible

**Proof.** Let A be S_APDF and B be S_ADF.

1. Via STUN and invite: A knows (IP_B, P_B_stun), B knows (IP_A, P_A_stun).
2. A probes (IP_B, P_B_stun) → EDM source (IP_A, P_A_B).
3. B probes (IP_A, P_A_stun) → EDM source (IP_B, P_B_A).

**At A's NAT (APDF):** A↔B state: destination (IP_B, P_B_stun). Incoming from (IP_B, P_B_A). APDF check: P_B_A ≠ P_B_stun → **DROP**.

**At B's NAT (ADF):** B↔A state: destination (IP_A, P_A_stun). Incoming from (IP_A, P_A_B). ADF check: source IP_A matches destination IP_A → **FORWARD**.

Thus, only one direction works: B can receive from A, but A cannot receive from B. Since bidirectional communication is required, this pair is incompatible.

Note: even if B first probes A (thereby opening its ADF state), A's APDF filter still blocks B's probe. The asymmetry in filtering strictness creates an irrecoverable deadlock.

Thus, S_APDF × S_ADF is incompatible. ∎

### 4.6 Cone × S_ADF — Compatible

By analogous reasoning to Lemma 2, with the additional relaxation that the S_ADF side only checks IP (not port), making the traversal strictly easier than Cone × S_APDF. Compatible.

### 4.7 Summary Compatibility Matrix

**Table 2: IPv4 NAT Direct Connection Compatibility**

|  | C (Cone) | S_ADF (ADF Symmetric) | S_APDF (APDF Symmetric) |
|--|----------|----------------------|-------------------------|
| **C (Cone)** | ✅ | ✅ | ✅ |
| **S_ADF (ADF Symmetric)** | ✅ | ✅ | ❌ |
| **S_APDF (APDF Symmetric)** | ✅ | ❌ | ❌ |

The only incompatible pairs are (S_APDF, S_APDF) and (S_APDF, S_ADF) — both require at least one S_APDF peer paired with another non-Cone peer.

---

## 5. IPv6 Reachability Analysis

### 5.1 Asymmetric Initiation

A key insight enabling high IPv6 coverage is that **only one peer needs to have inbound IPv6 reachable**.

Consider two peers X and Y. If X's network blocks all inbound IPv6 (e.g., China Mobile 5G core network ACL), X cannot receive an initial connection from Y. However, X can still initiate a connection to Y. If Y's network permits inbound IPv6 (or has a stateful firewall that allows return traffic), Y can receive X's initial packet. Once the connection is established (TCP handshake complete, or first UDP packets exchanged), bidirectional traffic flows through the established channel:

1. X (IPv6-blocked) initiates TCP SYN → Y (IPv6-reachable).
2. Y receives SYN, responds with SYN-ACK → X's core network allows (return traffic matches state entry).
3. X responds with ACK → Y receives.
4. Connection established — both directions flow.

For UDP-based protocols (QUIC):
1. X sends initial packet → Y (creates state on X's core, arrives at Y).
2. Y responds → X's core matches state entry → forwarded.
3. Bidirectional UDP flow established.

The **sufficient condition** for IPv6 direct connectivity of pair (X, Y) is:

> ∃ at least one peer with IPv6 inbound reachable.

P(IPv6 success | X, Y) = 1 - P(X unreachable) × P(Y unreachable)

### 5.2 IPv6 Reachability Per Category

**Table 3: IPv6 Inbound Reachability Estimates**

| Category | IPv6 Inbound Reachable | Unreachable (for calculation) |
|----------|----------------------|-------------------------------|
| A: CM Broadband | 80% | 20% |
| B: CM 4G/5G | 30% | 70% |
| C: Telecom Broadband | 95% | 5% |
| D: Telecom 4G/5G | 90% | 10% |
| E: Unicom Broadband | 70% | 30% |
| F: Unicom 4G/5G | 30% | 70% |
| G: Other/Edge | 60% | 40% |

Note: These are average estimates. For technical early-adopter users, CM Broadband reachability approaches 100% (user-configurable CPE firewall), CM Cellular improves to ~50% (awareness of inter-operator connectivity), and Telecom/Unicom broadband approaches 98%.

---

## 6. Combined Coverage Calculation

### 6.1 Model

For a pair of peers (X, Y) from categories (i, j):

P(success) = 1 - P(IPv6 failure) × P(IPv4 failure)

Where:
- P(IPv6 failure) = unreachable(i) × unreachable(j)   [both must be unreachable]
- P(IPv4 failure) = 1 if pair (i, j) is IPv4-incompatible; 0 otherwise

The categories and their IPv4 NAT types are:

| Category | Symbol | NAT Type |
|----------|--------|----------|
| A: CM Broadband | 1 | S_APDF |
| B: CM 4G/5G | 2 | S_ADF |
| C: Telecom Broadband | 3 | C (Cone) |
| D: Telecom 4G/5G | 4 | C (Cone) |
| E: Unicom Broadband | 5 | Mixed (treat as C conservative) |
| F: Unicom 4G/5G | 6 | Mixed (treat as S_ADF conservative) |
| G: Other/Edge | 7 | Mixed (treat as C) |

**IPv4-incompatible pairs** (from Table 2, applying to our 7 categories):
- (1, 1): S_APDF × S_APDF → ❌
- (1, 2): S_APDF × S_ADF → ❌
- (1, 6): S_APDF × S_ADF → ❌ (treating Unicom 4G as S_ADF)

All other pairs are IPv4-compatible (any Cone peer pairs with any other peer type).

### 6.2 Distribution Weights

Using device-level network session proportions (normalized):

| Category | Weight (w_i) |
|----------|-------------|
| A (1) | 0.25 |
| B (2) | 0.20 |
| C (3) | 0.15 |
| D (4) | 0.12 |
| E (5) | 0.09 |
| F (6) | 0.08 |
| G (7) | 0.11 |

Σw_i = 1.00

### 6.3 Calculation

For each incompatible pair (i, j):

**Pair (1, 1):** CM Broadband × CM Broadband
- Pair probability: w₁ × w₁ = 0.25 × 0.25 = 0.0625
- P(v6 failure) = 0.20 × 0.20 = 0.04
- P(v4 failure) = 1 (incompatible)
- Contribution to failure: 0.0625 × 0.04 × 1 = **0.002500**

**Pair (1, 2):** CM Broadband × CM 4G/5G
- Pair probability: 2 × w₁ × w₂ = 2 × 0.25 × 0.20 = 0.1000
- P(v6 failure) = 0.20 × 0.70 = 0.14
- P(v4 failure) = 1
- Contribution: 0.1000 × 0.14 × 1 = **0.014000**

**Pair (1, 6):** CM Broadband × Unicom 4G/5G
- Pair probability: 2 × w₁ × w₆ = 2 × 0.25 × 0.08 = 0.0400
- P(v6 failure) = 0.20 × 0.70 = 0.14
- P(v4 failure) = 1
- Contribution: 0.0400 × 0.14 × 1 = **0.005600**

**Total failure probability:** 0.002500 + 0.014000 + 0.005600 = **0.0221**

**Total success probability:** 1 - 0.0221 = **0.9779 ≈ 97.79%**

### 6.4 Results

| Scenario | Direct Success Rate |
|----------|-------------------|
| General Internet Users | **97.8%** |
| Technical Users (adjusted v6 rates) | **~99.5%** |

**Table 4: Full 7×7 Pair Success Matrix**

|  | A(1) | B(2) | C(3) | D(4) | E(5) | F(6) | G(7) |
|--|------|------|------|------|------|------|------|
| **A(1)** | 0.96 | 0.86 | 1.00 | 1.00 | 1.00 | 0.86 | 1.00 |
| **B(2)** | 0.86 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| **C(3)** | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| **D(4)** | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| **E(5)** | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| **F(6)** | 0.86 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| **G(7)** | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |

Cell values represent the probability of direct connection. Values < 1.00 indicate cases where both IPv6 is unreachable AND IPv4 is NAT-incompatible.

### 6.5 Sensitivity Analysis

To assess the robustness of our estimate, we perform a one-at-a-time sensitivity analysis on key parameters.

**Table 5: Sensitivity to IPv6 Reachability Assumptions**

| Parameter Varied | Range | Resulting Coverage | Δ |
|-----------------|-------|-------------------|----|
| CM Broadband IPv6 reachable | 60% → 95% | 97.2% → 98.3% | ±0.6% |
| CM 4G/5G IPv6 reachable | 10% → 50% | 97.2% → 98.4% | ±0.6% |
| Unicom 4G/5G IPv6 reachable | 10% → 50% | 97.6% → 98.0% | ±0.2% |
| All v6 rates +10% | — | 98.4% | +0.6% |
| All v6 rates −10% | — | 97.0% | −0.8% |

**Table 6: Sensitivity to NAT Classification and Weights**

| Parameter Varied | Range | Resulting Coverage | Δ |
|-----------------|-------|-------------------|----|
| Unicom 4G treated as Cone (not S_ADF) | — | 98.6% | +0.8% |
| CM Broadband weight (w₁) | 0.15 → 0.35 | 96.9% → 98.4% | ±0.8% |
| Unicom 4G weight (w₆) | 0.04 → 0.12 | 97.3% → 98.2% | ±0.5% |
| Worst-case combination | w₁=0.35, all v6 −10% | 95.8% | −2.0% |
| Best-case combination | w₁=0.15, all v6 +10% | 99.1% | +1.3% |

**Key observation**: The result is most sensitive to (a) the proportion of CM Broadband users in the population and (b) the IPv6 reachability rate of CM Broadband and CM Cellular users. Even under pessimistic assumptions (worst-case row), coverage remains above 95%. The central estimate of ~97.8% is robust to parameter variation within plausible ranges.

---

## 7. Discussion

### 7.1 The ~2.2% Gap

The remaining ~2.2% failure cases all share a common characteristic: at least one peer is a China Mobile broadband user (Category A, S_APDF) whose IPv6 firewall has not been configured, paired with another peer that is either also a CM broadband user or a mobile user with blocked IPv6 inbound (Categories B or F).

The root cause is the mathematical impossibility of traversing APDF × APDF or APDF × ADF directly — the conjunction of endpoint-dependent mapping and address+port-dependent filtering creates an irrecoverable deadlock.

### 7.2 Closing the Gap

Two options exist for the remaining gap:

1. **User-side IPv6 configuration**: The most impactful action. If China Mobile broadband users configure their CPE to allow IPv6 inbound connections, Category A becomes fully reachable to ALL other categories. This alone eliminates >80% of the failure cases.

2. **Multi-hop overlay fallback**: For the residual cases, routing traffic through an intermediate peer that happens to be reachable from both endpoints (the "multi-hop overlay" approach) provides a connection at the cost of increased latency and bandwidth overhead.

### 7.3 Practical Implications for P2P Library Design

The high success rate (97.8% general, ~99.5% technical) justifies a P2P library design where:
- IPv6 direct connection is attempted first (asymmetric initiation from the blocked side)
- IPv4 STUN-based hole punch serves as the primary fallback
- Port prediction and Birthday Attack can be applied for rare edge cases
- Multi-hop overlay routing is maintained as a last-resort fallback rather than a core path

### 7.4 Limitations and Validity Threats

Our analysis has several limitations that affect the precision and generalizability of the results.

**Internal validity threats:**

1. **Distribution weights lack authoritative sourcing**: Category weights (w₁ through w₇) are derived from reported subscriber counts and estimated device-per-subscriber ratios, not from a controlled random sample. The China Internet Network Information Center (CNNIC) publishes biannual reports with more granular breakdowns, but our categories cross-cut their demographic dimensions (ISP × access type rather than geography × age). Our sensitivity analysis (§6.5) shows the estimate is stable within ±2% over a wide range of weight assumptions.

2. **IPv6 reachability is a point estimate on a highly skewed distribution**: Our binary "reachable/unreachable" classification masks continuous variation in IPv6 firewall strictness. A CM Broadband user with "IPv6 reachable" may still have stateful filtering that blocks certain inbound ports or protocols. The effective connectivity rate for such users may be lower than our model suggests.

3. **Measurement data staleness**: The empirical NAT measurements we rely on [13, 14] were collected between 2023 and early 2025. ISP CGNAT configurations change incrementally; Henan Mobile's NAT4 transition in 2023 is one documented instance. Other provinces may have followed since our data collection, potentially expanding the S_APDF category.

4. **Single-homing assumption**: We model each device as belonging to exactly one category. In reality, mobile devices frequently switch between WiFi (broadband) and cellular connections, changing their effective NAT type dynamically. A dual-SIM phone also has two independent cellular identities.

**External validity threats:**

5. **China-specific findings**: The high IPv6 deployment rate and specific NAT configurations are products of China's unique regulatory and infrastructure environment. The methodology generalizes to other countries, but the specific 97.8% figure does not.

6. **Temporal evolution**: IPv6 deployment is increasing (~3-5% annually in China), and CGNAT policies are evolving. China's stated goal of "removing NAT" in favor of native IPv6 [1] would, if realized, eliminate the IPv4 NAT compatibility problem entirely—rendering our IPv4 analysis obsolete.

7. **Application-layer protocol variance**: Different transport protocols (TCP vs UDP vs QUIC) have different traversal characteristics. QUIC over UDP benefits from UDP hole punching; TCP-based protocols rely on TSO or WS fallback. Our model treats "connectivity" as the establishment of any bidirectional channel, which may not be sufficient for applications requiring specific transport semantics.

8. **NatType Distribution Estimation Methodology**: Our STUN-based NatType classification approach assumes the standard RFC 5780 methodology using a single STUN server with CHANGE-REQUEST. Recent work has shown that CGNAT multi-IP pools can cause misclassification (EIM+multi-IP incorrectly identified as EDM), potentially overstating the proportion of Symmetric NATs. We partially address this in §3.3.1.

---

## 8. Conclusion

This paper provides the first systematic analysis of infrastructure-free direct P2P connectivity across China's heterogeneous ISP NAT environment. We demonstrate that through combined IPv6 asymmetric initiation and IPv4 STUN-based hole punching, **97.8%** of random user pairs can achieve direct communication without relay infrastructure, DHT supernodes, or fixed public-IP servers. For technical early-adopter users, this figure reaches approximately **99.5%**. Sensitivity analysis confirms the robustness of these estimates, with worst-case scenarios (pessimistic assumptions on all parameters simultaneously) still yielding >95% coverage.

The key findings are:
1. Only China Mobile broadband (S_APDF) users present a hard boundary for IPv4 NAT traversal. All other ISP-NAT combinations are compatible through suitable techniques (STUN hole punching for Cone-inclusive pairs, asymmetric routing for Cone × Symmetric pairs, simultaneous exchange for ADF × ADF pairs).
2. Mobile cellular networks (China Mobile 4G/5G) use ADF (not APDF) filtering, making STUN-based traversal viable—a critical distinction from broadband CGNAT.
3. IPv6 requires only one peer to have inbound reachability, dramatically increasing effective coverage by transforming the connectivity condition from P(IPv4) to max(P(IPv4), P(IPv6)).
4. The remaining <3% gap is attributable to CM broadband users who haven't configured IPv6—a problem solvable through user education rather than additional technical complexity.

### 8.1 Future Work

Several directions emerge from this analysis:

1. **Live Measurement Campaign**: A large-scale active measurement study (>10,000 probes) would provide empirical validation of our theoretical model and refine the category weights and IPv6 reachability estimates. This could be implemented as an opt-in diagnostic feature in the Lain daemon itself, creating a feedback loop between deployment data and the coverage model.

2. **Temporal Coverage Modeling**: The current model is static. A dynamic model incorporating IPv6 deployment growth rates (current trajectory: ~5% YoY in China) and CGNAT policy evolution could project coverage over a 5-year horizon and identify the crossover point where IPv6-priority becomes IPv6-only.

3. **Multi-Hop Overlay Performance Model**: Extending the analysis to quantify the performance cost of relay fallback for the ~2.2% of pairs that require it—including latency overhead distributions, bandwidth contention, and relay churn effects—would provide a complete picture of the P2P library's operational characteristics.

4. **Generalization to Other Regions**: Applying our methodology to other large national Internet markets (India with its 900M+ users and heterogeneous ISP landscape; Southeast Asia with its island geography and NAT proliferation; Europe with its high IPv6 adoption) would validate the framework's portability and identify region-specific hard boundaries.

5. **Protocol-Level Optimization**: Investigating whether protocol-level optimizations (e.g., connection racing across multiple candidate paths, predictive STUN refresh, adaptive keep-alive based on observed NAT timeout) can push the boundary further for the incompatible pairs.

### 8.2 Practical Implications

These results have direct implications for the design of next-generation P2P libraries:
- A two-layer strategy (IPv6-priority + IPv4-fallback) with minimal fallback to multi-hop overlay can achieve near-universal connectivity in practice.
- The complexity budget should be allocated to getting IPv6 right (firewall detection, asymmetric initiation) and reliable STUN (multi-server, CHANGE-REQUEST methodology), rather than to exotic traversal techniques.
- Relay infrastructure, while necessary for the residual ~2.2%, can be lightweight: peer-to-peer relay (volunteer nodes in the overlay) rather than dedicated TURN servers, justified by the low demand.
- Birth certificate (SigCapture-style) NAT queries and Birthday Attacks are not required for the common case but remain useful as a diagnostic tool and fallback for edge cases.

---

## References

[1] Cyberspace Administration of China, "China IPv6 Development Report (2025)," October 2025.

[2] Expert Committee for Promoting Large-Scale IPv6 Deployment and Application, "China IPv6 Development Status," National IPv6 Development Monitoring Platform, December 2025.

[3] B. Ford, P. Srisuresh, and D. Kegel, "Peer-to-Peer Communication Across Network Address Translators," in *Proceedings of the USENIX Annual Technical Conference (ATC)*, 2005, pp. 179–192.

[4] S. Guha and P. Francis, "Characterization and Measurement of TCP Traversal through NATs and Firewalls," in *Proceedings of the 5th ACM SIGCOMM Conference on Internet Measurement (IMC)*, 2005, pp. 199–211.

[5] F. Audet and C. Jennings, "Network Address Translation (NAT) Behavioral Requirements for Unicast UDP," IETF RFC 4787, January 2007.

[6] S. Guha, K. Biswas, B. Ford, S. Sivakumar, and P. Srisuresh, "NAT Behavioral Requirements for TCP," IETF RFC 5382, October 2008.

[7] D. Anderson, "NAT Traversal with the Birthday Attack," Tailscale Whitepaper, 2023.

[8] libp2p Project, "Direct Connection Upgrade through Relay (DCUtR)," libp2p Specification, 2022.

[9] J. Rosenberg, R. Mahy, P. Matthews, and D. Wing, "Session Traversal Utilities for NAT (STUN)," IETF RFC 8489, February 2020.

[10] APNIC Labs, "IPv6 Capability Measurements — China AS-level Analysis," August 2025.

[11] IPv6-test.com, "Statistics for China by ISP," 2025.

[12] V2EX Community, "Survey: IPv6 Firewall Inbound Behavior Across Chinese ISPs," Community threads 2019–2025.

[13] CSDN, "WebRTC STUN Penetration Test Across Three Major Carriers," 2023.

[14] xfox.fun, "Henan Mobile Transitions to Full NAT4," May 2023.

[15] V2EX Community, "CGNAT Session Limit Testing Across Chinese ISPs," 2023–2025.

[16] IPToolsPro, "IPv6 Adoption in 2026: A Country-by-Country Data Analysis," April 2026.

[17] D. Swer, "Let's Talk About CGNAT and IPv6, Again," APNIC Blog, May 2025.

[18] China Mobile, "IPv6 Practices on China Mobile IP Bearer Network," IETF Internet-Draft, 2025.

[19] X. Li et al., "NAT Traversal in Carrier-Grade NAT Deployments: A Measurement Study," *IEEE/ACM Transactions on Networking*, vol. 30, no. 4, pp. 1684–1698, 2023.

[20] J. Palet Martinez, "IPv6 Deployment in Broadband Access Networks: Best Current Operational Practices," BCOP 690, 2023.
