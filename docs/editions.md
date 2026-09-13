# Public and Enterprise

The Public edition includes the standalone controller, console, Linux gateway, Android libraries/apps and Node client. It can enroll and manage devices without an Enterprise service. HTTPS, permissions, MFA, admission checks, policy enforcement, revocation and audit events remain available to Public users.

Enterprise is a separately supplied deployment package for environments that need coordinated service continuity:

| Enterprise capability | Operational purpose |
| --- | --- |
| Active–Standby HA | Run a redundant service group with a stable VPN address and server identity |
| Replica acknowledgement | Confirm enrollment and policy mutations on the replica before reporting success |
| Fencing and forwarding leases | Isolate an uncertain peer and stop forwarding when the active node loses authority |
| Cluster lifecycle integration | Coordinate service start, stop and monitoring with the cluster manager |

The supported HA design uses Linux hosts, a properly configured database replica, persistent keys and a real fencing/quorum design. Failover can briefly interrupt tunnels; devices may reconnect. Recovery times and support commitments depend on the deployment agreement. A Windows administration app alone does not form a production HA cluster.

The Public build contains only a standalone adapter. Requesting `AIDOTVPN_HA_ENABLED=true` in that build fails with `enterprise_feature_required`; it cannot turn the Public build into Enterprise. The console's HA page explains the Enterprise offering and provides an inquiry link.

Automated backup/restore, multi-site disaster recovery, OS-level mobile wipe/lock, application distribution, kiosk management, SAML federation and Apple device management are not advertised as implemented Enterprise features in this release. Discuss requirements before treating them as part of a delivery.

Contact [mike.jung.global@gmail.com](mailto:mike.jung.global@gmail.com?subject=AidotVPN%20Enterprise%20inquiry) with the device count, network environment, host platforms, availability objectives and support needs. Public remains usable under Apache-2.0, including commercial use under its terms.
