# bottle-agent

`bottle-agent` is the agent responsible for managing advanced analysis and
pipelines around the [`bottle`](https://github.com/cochaviz/bottle) interface:

> bottle is a Go toolkit for building long-lived sandbox images and repeatedly
> running botnet or malware samples inside them. It wraps libvirt, nftables, and
> a curated set of Debian-based VM specifications so you can build images, lease
> them for sandbox runs, launch short-lived analyses, or hand those runs off to
> a daemon for continuous monitoring.

The agent fulfills several roles:

- **API**: Provides an API for submitting analysis jobs and managing agent state.
- **Orchestration**: Ensure submitted samples are analyzed, even in the event of a
  crash or restart.
- **C2 Detection and Monitoring**: Analyzes logs to detect command and control
  (C2) communications within the sandboxed environment, and opening firewall
  rules to allow communication with the C2 server.
- **Miscellaneous**: 
  - Provides additional functionality such as taking a sample hash and retrieving it from MalwareBazaar.
  - Continuously watches Malwarebazaar for new samples, running them automatically.

In the end, the goal of the `bottle-agent` is to provide a complete pipeline that takes a sample, detects C2 actvitity and ensures that 

## C2 Detection

In the end, the aim is to allow bots to communicate with their C2 server, and
monitor the communication for suspicious activity. It is assumed that the C2
server is not known beforehand, meaning that it has to be inferred from the
logs. This happens in two stages:

1. **Isolated Execution**: In this stage, the agent runs the sample in a
   sandboxed environment without any network access. Any outgoing network
   traffic is routed to inetsim, which simulates a primitive network
   environment. Any IP addresses that cannot be reasonably attributed to, for
   example, NTP traffic, are considered candidate for C2 activity.
2. **Pinholed Execution**: We do not at any point explicitly determine the
   'validity' of a C2 server, instead, we simply kill the sandbox if no
   beaconing activity is detected. Not only does this simplify 'detection' of C2
   activity, but it also ensures that the sandbox is killed when the C2 server
   dies.

The agent thus carries the responsibility of assessing 'candidate' IP addresses
from the available logs, starting pinholed sandboxes, and killing any sandbox that
does not beacon.

## Basic Instrumentation Setup

For now, we have the following basic setup, allowing us to capture much of the
interesting activities that might be indicative of C2 activity, or attacks on
target systems.

```
cli:
    - command: tcpdump -i {{ .VmInterface }} -w c2_traffic.pcap host {{ .VmIp }} and host {{ .C2Ip }}
      output: file
    - command: gomon {{ .VmInterface }} {{ .VmIp }} --c2-ip {{ .C2Ip }} --sample-id {{ .SampleName }} --save-packets 100 --eve-log-path /var/log/suricata/eve.json --capture-dir {{ .LogDir }}/captures
      output: file
suricata:
    - config: suricata.yml
      output: file
```

The definition of the `suricata.yml` file and the corresponding rules can be
found in the `instrumentation` directory.

All logs end up in the global `eve.json` file in `/var/log/suricata/eve.json`.
This includes the alerts/logs from the `gomon` command. While there are also
pcaps which are saved to the `LogDir` directory of that particular analysis,
these are not used for this particular analysis.

## Orchestration

In order to orchestrate the analysis, we need to keep a ledger of all
should-be-running analyses, with their corresponding configuration details. This
is highly dependent on the API defined by the `bottle` daemon (details included
in `daemon_impl.txt`). For now, the ledger shall be a simple text file, with
each line containing the sample ID and the corresponding configuration details.

The agent reads this file on intervals and ensures all corresponding analyses
are running or stopped, if necessary. Labeling an analysis in the ledger as
`stale` means that the analysis has seized to be relevant, and it should be
stopped. We will allow removal of stale analyses (or any non-running analysis)
from the ledger, but not automatically to ensure we have insight into the status
of the analysis.

Before analyses can be removed they have to be stopped first. This is done by
sending a `stop` command to the `bottle` daemon, which will stop the analysis.
Then, we can remove it from the ledger with the `remove` command.

For now, we follow the constraint that we cannot have multiple analyses of the
same sample and c2. If a sample without c2 is running, no other analysis with
that sample can be started (regardless of c2).

### Batch Analyses

Another important utility should be the ability to `batch` many analyses. If we
want to analyse many samples, we can run a batch analysis which ensures that
samples are analysed in sequence to save on resources.

By providing a folder containing multiple samples, the agent will automatically
queue them for analysis. Before running the next analysis, the agent will wait
for the current analysis to finish. To guarantee that analyses are actually
finished, it uses the `sample_timeout` and `sandbox_timeout` parameters when
submitting the analysis to the `bottle` daemon.

## API

The API will be a simple REST API, which will expose any of the aforemention functionality through the following endpoints:

- `GET /health`: Check the health of the agent.
- `GET /analyses`: Retrieve a list of all analyses.
- `POST /analyses`: Create a new analysis.
- `PUT /analyses/{id}`: Update an existing analysis.
- `DELETE /analyses/{id}`: Delete an analysis.
- `POST /analyses/batch`: Queue multiple analyses.


## Miscellaneous

In order to make it easy to analyse new samples, the agent will not only be able
to take files as a parameter, but also URLs and file hashes. If it's a file
hash, it will attempt to look this file up in MalwareBazaar and retrieve it.

This ties into another miscellaneous feature, which is the ability to watch for
new samples on MalwareBazaar (checks once every hour) that are then analyzed.
