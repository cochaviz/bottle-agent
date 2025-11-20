# bottle-agent

`bottle-agent` is the orchestration and monitoring layer that sits on top of a
[`bottle`](https://github.com/cochaviz/bottle) deployment. It keeps a ledger of
analyses, submits runs to the bottle daemon, watches Suricata logs for C2
activity, and optionally ingests new samples from MalwareBazaar. Use it when you
need to keep long-running sandboxes alive, automatically requeue samples, and
collect forensic data without babysitting the bottle daemon.

> Note that the `bottle-agent` more of an experiment than a production-ready
  tool. Most of this code base is generated and thus not perfectly vetted. I
  have plans to rewrite it in Elixir for easy scalability and reliability.

## Capabilities

- **REST API + CLI client** – submit, list, update, delete, and batch analyses
  through `/analyses` endpoints or the bundled `bottle-agent client` subcommand.
- **Ledger-driven orchestration** – JSON-lines ledger tracks desired state;
  orchestrator reconciles it against the running bottle daemon so analyses
  survive restarts.
- **C2 activity monitoring** – tails Suricata `eve.json`, tracks signature IDs
  per sample, and marks analyses stale when beaconing stops or timeouts hit.
- **MalwareBazaar integration** – accepts hash-based submissions, downloads
  samples automatically, and can watch the feed for new material.
- **Batching** – queue directories of samples or lists of hashes, enforcing
  single-run-per-sample/C2 rules to conserve resources.
- **Pluggable instrumentation** – pass the instrumentation profile expected by
  bottle (e.g. `instrumentation/default`) for each run.

## Installation

### Requirements

- Go 1.21+ toolchain (module targets Go 1.24).
- Running bottle daemon (`bottle daemon serve …`) with its unix socket exposed.
- Suricata logs accessible at `/var/log/suricata/eve.json` (or another path
  configured in `config.yaml`).
- Optional: MalwareBazaar API key (`MALWAREBAZAAR_API_KEY` env var or
  `config.yaml` field) if you want hash ingestion/watchers.

### Steps

```shell
git clone https://github.com/cochaviz/bottle-agent.git
cd bottle-agent
go install .               # installs $GOBIN/bottle-agent
# or
go build -o bottle-agent . # builds local binary in the repo
cp config.example.yaml config.yaml  # and edit to match your environment
```

Inside `config.yaml`:

- Update `monitoring.eve_path` and timeout rules to match your Suricata setup.
- Configure `malwarebazaar.*` (sample directory, API key) and
  `malwarebazaar.watcher.*` (instrumentation, timeouts, tags) if you
  plan to retrieve hashes automatically.
- Point `instrumentation` fields at a profile known to the bottle daemon.

## Usage

### Serving the API / orchestrator

```shell
./bottle-agent serve \
  -listen ":8080" \
  -ledger data/ledger.jsonl \
  -daemon-socket /var/run/bottle/daemon.sock \
  -config config.yaml
```

- `-ledger` points at the JSON-lines ledger file (created if absent).
- `-daemon-socket` must match the bottle daemon socket path.
- `-config` loads monitoring/MalwareBazaar settings (optional).

### CLI client

```shell
./bottle-agent client status                    # list analyses
./bottle-agent client add -sample foo -path sample.exe
./bottle-agent client add -sample bar -hash <sha256>
./bottle-agent client delete <id>
./bottle-agent client add-bulk -dir /path/to/samples
./bottle-agent client add-bulk -hashes hash1,hash2
```

Use `-server http://host:port` for remote agents (defaults to
`http://127.0.0.1:8080`).

### Running alongside bottle

1. Start the bottle daemon with your preferred instrumentation set.
2. Launch `bottle-agent serve …` on the same host, pointing `-daemon-socket` at
   the bottle daemon socket.
3. Interact via the REST API or CLI client; the orchestrator translates entries
   into `start_analysis` / `stop_analysis` commands.
4. Export `MALWAREBAZAAR_API_KEY` and enable the watcher in `config.yaml` if you
   want automatic sample ingestion.

### Example systemd service

You can let systemd keep the orchestrator online by dropping a unit such as
`/etc/systemd/system/bottle-agent.service`:

```ini
[Unit]
Description=bottle-agent orchestrator
Wants=network-online.target
After=network-online.target
After=suricata.service bottle-daemon.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/bottle-agent
EnvironmentFile=-/etc/default/bottle-agent
ExecStart=/root/go/bin/bottle-agent serve \
    -listen ":8080" \
    -ledger /opt/bottle-agent/data/ledger.jsonl \
    -daemon-socket /var/run/bottle/daemon.sock \
    -config /opt/bottle-agent/config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

- Adjust the service `User`/`Group`, paths, and `ExecStart` arguments to match
  your install layout (the `EnvironmentFile` is optional but convenient for
  passing credentials such as `MALWAREBAZAAR_API_KEY`).
- Reload systemd (`sudo systemctl daemon-reload`) and enable the unit
  (`sudo systemctl enable --now bottle-agent.service`) to have the agent start
  immediately and on future boots.

## Design Details (Deep Dive)

The sections below retain the original deep explanation of how the agent works
internally. They are useful when you need to understand *why* the system behaves
in a certain way, or when modifying instrumentation/monitoring internals.

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

## Usage (Legacy Summary)

For quick reference, the legacy commands remain valid:

```shell
go build -o bottle-agent .
./bottle-agent serve -listen ":8080" -ledger data/ledger.jsonl -daemon-socket /var/run/bottle/daemon.sock -config config.yaml
./bottle-agent client status
./bottle-agent client add ...
```

The modern `bottle-agent` binary simply inlines these commands.

### Running Alongside bottle

1. Start the bottle daemon (refer to the bottle README) ensuring it can access
   your VM definitions and instrumentation profiless.
2. Launch `bottle-agent serve …` on the same host, pointing `-daemon-socket` at the
   bottle daemon’s unix socket.
3. Submit jobs via the REST API or the CLI client. The orchestrator will call
   `start_analysis` / `stop_analysis` on the daemon as needed while keeping the
   ledger in sync.
4. Optionally export `MALWAREBAZAAR_API_KEY` to allow hash-based submissions and
   enable the watcher configured in `config.yaml`.
