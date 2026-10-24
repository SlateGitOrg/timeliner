# Ground truth: synthetic intrusion on `web01`

All artifacts under `evidence/` are synthetic and were produced by `timeliner fixtures` (seeded, deterministic). Local-time logs use `America/New_York`; the incident window is in EST (UTC-5).

SSH brute force from 203.0.113.45 leads to a password login as deploy, payload staging in /tmp, sudo to a root shell, netcat install, backdoor account sysbackup (sudo group), root crontab persistence that fires after midnight, then a public-key login as sysbackup from 192.0.2.99 that reads /etc/shadow and shreds a rotated log.

| Step | UTC | Local (America/New_York) | Expected kind | Expected tag | What happened |
|---|---|---|---|---|---|
| S01 | 2025-01-01T04:02:12Z | 2024-12-31 23:02:12 | `ssh_login_failure` | — | SSH brute force begins: first failed password from the attacker |
| S02 | 2025-01-01T04:02:50Z | 2024-12-31 23:02:50 | `ssh_login_failure` | `ssh-bruteforce` | Brute-force threshold crossed (5 failures from one IP within 5 minutes) |
| S03 | 2025-01-01T04:07:12Z | 2024-12-31 23:07:12 | `ssh_login_success` | `ssh-new-ip` | Password login as deploy from an IP never seen for that account |
| S04 | 2025-01-01T04:07:13Z | 2024-12-31 23:07:13 | `login` | — | wtmp records the interactive session on pts/1 |
| S05 | 2025-01-01T04:08:05Z | 2024-12-31 23:08:05 | `shell_command` | — | Reconnaissance: deploy runs `id` |
| S06 | 2025-01-01T04:09:02Z | 2024-12-31 23:09:02 | `shell_command` | `download` | Payload downloaded into /tmp |
| S07 | 2025-01-01T04:09:03Z | 2024-12-31 23:09:03 | `file_activity` | `file.temp-hidden` | File system: hidden script /tmp/.x.sh is born |
| S08 | 2025-01-01T04:09:30Z | 2024-12-31 23:09:30 | `shell_command` | `temp-exec` | Payload made executable |
| S09 | 2025-01-01T04:10:44Z | 2024-12-31 23:10:44 | `sudo_command` | `root-shell` | deploy escalates: sudo /bin/bash (root shell) |
| S10 | 2025-01-01T04:11:31Z | 2024-12-31 23:11:31 | `package_transaction` | `tool-install` | APT transaction installs netcat-openbsd |
| S11 | 2025-01-01T04:11:33Z | 2024-12-31 23:11:33 | `package_install` | `tool-install` | dpkg unpacks netcat-openbsd |
| S12 | 2025-01-01T04:13:05Z | 2024-12-31 23:13:05 | `user_created` | `new-user` | Backdoor account sysbackup created |
| S13 | 2025-01-01T04:13:41Z | 2024-12-31 23:13:41 | `password_changed` | `account-change` | Password set for sysbackup |
| S14 | 2025-01-01T04:14:10Z | 2024-12-31 23:14:10 | `user_modified` | `admin-group` | sysbackup added to the sudo group |
| S15 | 2025-01-01T04:15:22Z | 2024-12-31 23:15:22 | `crontab_change` | `crontab` | Root crontab replaced |
| S16 | 2025-01-01T04:16:40Z | 2024-12-31 23:16:40 | `logout` | — | deploy session ends (wtmp logout paired with the login) |
| S17 | 2025-01-01T05:05:01Z | 2025-01-01 00:05:01 | `cron_command` | `cron-temp` | cron executes /tmp/.x.sh as root after midnight |
| S18 | 2025-01-01T05:31:15Z | 2025-01-01 00:31:15 | `ssh_login_success` | — | sysbackup logs in by public key from a second external IP |
| S19 | 2025-01-01T05:31:16Z | 2025-01-01 00:31:16 | `login` | — | wtmp/utmp record the sysbackup session on pts/2 |
| S20 | 2025-01-01T05:33:02Z | 2025-01-01 00:33:02 | `sudo_command` | `sudo-to-root` | sysbackup reads /etc/shadow through sudo |
| S21 | 2025-01-01T05:34:10Z | 2025-01-01 00:34:10 | `shell_command` | `anti-forensics` | Anti-forensics: rotated auth log shredded |
| S22 | 2025-01-01T05:34:13Z | 2025-01-01 00:34:13 | `file_activity` | — | File system: the shredded log's inode changes (deleted entry) |

Background noise (cron every 15 minutes, single-attempt internet scanners from 198.18.0.0/15, the administrator `alice` logging in daily from 198.51.100.7, a routine `deploy` release on Dec 30 from 198.51.100.23, an `apt upgrade` on Dec 29) is mixed in so that the story has to be found, not just listed.
