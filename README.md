# rule-placement

Works out **which stub firewalls a requested firewall rule has to be created on**, from
the rule's source and destination prefixes. Pure HCL - no providers, no external data
sources, no wrapper scripts.

## Model

Each firewall in `firewalls.yaml` has an `ability` - `stub`, `internet`, or both:

* **stub** - it has a list of directly connected subnets (can be summarized). A rule
  lands here when either side **overlaps** one of them.
* **internet** - it owns "the internet": everything outside its `internet_exclude`
  (RFC 1918, CGNAT, documentation ranges, ...). A side is internet unless it sits wholly
  inside one excluded prefix.
* **both** - an internet edge that also connects subnets, e.g. FW-I2 with a DMZ on
  non-public IPs.

Transit networks carry **no** firewall, so there are no transit hops to traverse.

Overlap, not containment. The test is symmetric, so one expression covers both
directions:

* a requested `/30` sitting inside a connected `/24`
* a requested supernet such as `10.0.0.0/8` swallowing many connected subnets

```
two prefixes overlap  <=>  a.first <= b.last && b.first <= a.last
```

### Placement rules

1. **Stub side.** Every firewall whose connected subnets overlap a side owns that side.
2. **Internet side.** Which internet firewall carries it depends on the *other* side:
   * the other side sits only on internet-capable firewalls (a DMZ) - only those, since
     traffic breaks out right there
   * the other side touches any stub-only firewall - **every** internet firewall, because
     the exit path from a stub is not modelled
   * the other side matches no stub - nothing (internet-to-internet, or a typo)

### Address sets

`address_sets` maps a name to CIDRs. A member may name another set (one level of
nesting), and `internet_exclude` accepts set names or CIDRs:

```yaml
firewalls:
  FW-I2:
    ability: [internet, stub]
    subnets: ["100.64.2.0/24"]
    internet_exclude: [internal_subnets]
address_sets:
  rfc1918: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
  internal_subnets: [rfc1918, cgnat, ...]
```

## Layout

| Path | Purpose |
| --- | --- |
| `modules/cidr-match/` | The "function". Inputs: normalised firewall inventory + a list of prefixes. Outputs stub hits, internet hits and unmatched prefixes. |
| `firewalls.yaml` | `firewalls:` name -> ability, connected subnets, internet exclusions. `address_sets:` named CIDR lists. |
| `rules/<TICKET>.yaml` | One file per request. Rules live under the `net:` key. |
| `main.tf` | Loads the YAML, expands address sets, calls the module per rule (source side and destination side), applies the placement rules. |

Terraform has no user-defined functions, so `modules/cidr-match` is invoked with
`for_each` over the ruleset - that is the idiomatic way to get a reusable,
parameterised computation in pure HCL.

## Usage

```bash
terraform init
terraform apply -auto-approve   # no resources; this only materialises the outputs
terraform output by_firewall
```

Rule keys are `<ticket>/<rule name>`, derived from the filename plus the YAML key
(YAML comments are discarded by `yamldecode`, so the ticket has to come from the
filename).

### Outputs

* **`by_firewall`** - firewall -> rule keys to render on it. This is the map to hang
  `for_each` off when generating real policy objects.
* **`placement`** - per rule: the firewall set, the `role` of each firewall
  (`egress` / `ingress` / `intra`), which connected subnets actually matched on each
  side (`src_hits` / `dst_hits`, with `"internet"` where the internet side matched), the
  side's `unmatched` prefixes.
* **`unplaced_rules`** - rules that land on no firewall. Almost always a typo in the
  request; worth failing a pipeline on.
* **`unmatched_prefixes`** - rules with prefixes that match nothing (reserved or
  documentation space, an unknown private range). The rest of the rule is still placed,
  so this is worth reviewing even when `unplaced_rules` is empty.

`role` is a placement hint, not policy. It says which side of the rule a firewall owns:
`egress` = source side, `ingress` = destination side, `intra` = both (for an internet
firewall, "internet" counts as one of its sides). It does not decide zone or interface
names.

## Implementation note

HCL has no bitwise operators, so a CIDR is turned into an integer range by arithmetic:
the dotted quad becomes an integer, the prefix length becomes a block size via
`pow(2, 32 - len)`, and the network address is `floor(ip / size) * size`. That masking
step means unaligned input (`10.1.1.130/25`) is handled correctly rather than silently
mis-compared.

## Limitations

**IPv4 only.** Input is validated with `can(cidrnetmask(c))`, which rejects IPv6 and
malformed values loudly at plan time. IPv6 would need 128-bit arithmetic, which is not
viable in HCL locals - that is the point to reach for a provider-defined function
instead.

**Internet exit is not modelled.** With more than one internet firewall, internal-to-internet
rules land on all of them. Pinning a stub to one exit would need an extra inventory field.

**Exclusion check is per prefix.** A queried prefix spanning two adjacent excluded blocks
without fitting in either would count as internet. It does not happen with the IANA list
above.

## Verified behaviour

Confirmed against the inventory in `firewalls.yaml` (three stubs, one internet firewall,
one internet firewall with a DMZ):

| Case | Expected | Result |
| --- | --- | --- |
| `/30` -> `/30` within one connected subnet | that firewall, `intra` | pass |
| `/30` -> `/30`, different subnets on one firewall | single firewall, `intra` | pass |
| unaligned host bits (`10.1.1.130/25`) | masks, then matches | pass |
| `/30` -> `/30` across two firewalls | both, `egress` + `ingress` | pass |
| `10.0.0.0/8` source | every firewall connecting a `10/8` subnet, no internet firewall | pass |
| stub -> public IP | stub + every internet firewall | pass |
| public IP -> stub | every internet firewall + stub | pass |
| public IP -> DMZ | DMZ firewall only, `intra` | pass |
| DMZ -> public IP | DMZ firewall only, `intra` | pass |
| stub -> DMZ | stub `egress` + DMZ firewall `ingress` | pass |
| `0.0.0.0/0` -> DMZ | every stub + DMZ firewall, not the other internet firewall | pass |
| public -> public | `unplaced_rules` | pass |
| unknown private range -> public | `unplaced_rules`, `unmatched_prefixes` | pass |
| documentation IP next to a public one | public part placed, doc IP in `unmatched_prefixes` | pass |
| unknown address set name, bad `ability`, subnets without `stub` | plan-time validation error | pass |
