# xproxy-fleet

## NAME

xproxy-fleet - fleet controller: configuration bundles and status for many xproxy nodes

## SYNOPSIS

`xproxy-fleet serve` `-dir` *DIR* `-listen` *ADDR* `-cert` *PEM* `-key` *PEM* `-ca` *PEM* [`-any-name`] [`-name-map` *FILE*] [`-scan` *D*] [`-admin-socket` *PATH*]

`xproxy-fleet nodes` [`-admin-socket` *PATH*] [`-json`]

`xproxy-fleet node` *ID* [`-admin-socket` *PATH*] [`-json`]

`xproxy-fleet bundle` *ID* [`-admin-socket` *PATH*]

`xproxy-fleet scan` [`-admin-socket` *PATH*]

`xproxy-fleet validate` [`-dir` *DIR*]

`xproxy-fleet version`

## DESCRIPTION

`xproxy-fleet` runs on a management host. Every `xproxy`(8) node with a
`fleet` section long polls it for the configuration bundle assigned to
the node and reports its status; the controller never connects to a
node. The directory holds:

| Path | Content |
|------|---------|
| *DIR*`/common/` | Files every node receives |
| *DIR*`/nodes/`*ID*`/` | A node's own files, overriding common ones; `xproxy.yaml` is its configuration |
| *DIR*`/status/` | The last report per node, kept across restarts |
| *DIR*`/fleet.sock` | The operator socket the query commands use |

Editing the files is the push: the controller rescans every `-scan`
interval, a bundle whose files no longer parse is not served (the last
good one stays and the error shows in `nodes`), and the agents apply a
changed bundle within seconds through the ordinary reload path, rolling
back the files when the proxy refuses the configuration.

Agents authenticate with a client certificate from `-ca`; the
certificate's common name or DNS name must equal the node id, unless
`-name-map` names that exception for that one node, or `-any-name`
turns the binding off for every node at once.

## COMMANDS

| Command | Description |
|---------|-------------|
| `serve` | Run the controller |
| `nodes` | List every node with its state (`in sync`, `behind`, `pending`, `failed`, `stale`, `unassigned`, `never seen`), digests, version, counters and errors |
| `node` *ID* | One node in detail |
| `bundle` *ID* | The files of a node's current bundle (paths, modes, sizes) |
| `scan` | Rescan the directory now and list the nodes |
| `validate` | Parse every node's bundle without a running controller; exit 1 when one is invalid |
| `version` | Print the version |

## OPTIONS

| Option | Description |
|--------|-------------|
| `-dir` *DIR* | Controller directory. Default `/var/lib/xproxy-fleet`. |
| `-listen` *ADDR* | Node listener. Default `:8447`. |
| `-cert`, `-key`, `-ca` *PEM* | Controller certificate, key and the CA that issues node certificates. Required for `serve`. |
| `-any-name` | Accept any certificate from the CA for any node id. Every authorisation is then warned about, because one stolen node certificate can fetch every node's bundle and report as any node; prefer `-name-map`. |
| `-name-map` *FILE* | File of `node_id certificate_name` lines (`#` comments): the named certificate may act for that node id. One exception at a time instead of turning the binding off for every node. Each use is counted and warned about. |
| `-scan` *D* | Directory rescan interval. Default `2s`. |
| `-admin-socket` *PATH* | Operator socket. Default *DIR*`/fleet.sock`. |
| `-json` | Machine readable output. |

## FILES

`/var/lib/xproxy-fleet`, `/etc/systemd/system/xproxy-fleet.service`

## SEE ALSO

`xproxy`(8), `xproxyctl`(8), `xproxy.yaml`(5) (the `fleet` section)
