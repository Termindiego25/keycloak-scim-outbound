# 🔐 Keycloak SCIM Outbound Plugin

A lightweight **Keycloak extension** that provisions users and groups to external applications via the **SCIM v2** protocol. This plugin allows Keycloak to **push user lifecycle changes** (create, update, delete, deactivate) to external systems like **Passbolt**, **Nextcloud**, or any other SCIM-compliant service — all configurable directly from the **Keycloak Admin Console**.

---

## 🚀 Features

- 🔁 **Automatic user provisioning** — Create, update, or deactivate users in external SCIM targets.
- 👥 **Group-based filtering** — Provision only members of a specific Keycloak group.
- ⚙️ **UI configuration** — Configure endpoints, tokens, and mapping directly from *User Federation*.
- 🧩 **Customizable userName strategy**
  - `username` → use Keycloak username
  - `email` → use user's email as SCIM `userName`
  - `attribute` → use a custom Keycloak user attribute
- 🧱 **SCIM v2 compatible** — Works with `/Users`, optional `/Groups` sync, and `/ServiceProviderConfig` endpoints.
- 🔒 **Token-based authentication (Bearer)** — no password sync required.
- 📂 **LDAP/AD support** — Optional [LDAP/AD support](#-optional-ldap--active-directory-integration) via a built-in `LdapSyncNotifierMapper`.
- 🗂️ **Optional SCIM Group sync** — Push Keycloak group create/rename/delete and membership changes to SCIM `/Groups`. Opt-in, disabled by default. Supports both event-driven changes and **LDAP-driven** membership changes.

---

## 🧰 Installation

### 1. Build the plugin

```bash
mvn clean package
```

This generates a `.jar` under:

```text
target/keycloak-scim-outbound-<version>.jar
```

### 2. Deploy to Keycloak

Copy the JAR file to your Keycloak providers directory, for example:

```bash
cp target/keycloak-scim-outbound-<version>.jar /opt/keycloak/providers/
```

Then rebuild the provider cache:

```bash
/opt/keycloak/bin/kc.sh build
```

Finally, restart Keycloak:

```bash
/opt/keycloak/bin/kc.sh start
```

---

## ⚙️ Configuration

Once deployed:

1. Open the **Keycloak Admin Console**.
2. Go to **User Federation → Add provider → keycloak-scim-outbound**.
3. Fill in the following fields:

| Field | Description | Required |
| --- | --- | --- |
| **SCIM Base URL** | Base endpoint of your SCIM API, e.g. `https://app.example.com/scim/v2` | ✅ |
| **SCIM Token** | Bearer token for authenticating with the SCIM target | ✅ |
| **Filter Group (optional)** | Only users in this group will be provisioned | ❌ |
| **userName Strategy** | How to build SCIM `userName` (`username`, `email`, or `attribute`) | ✅ |
| **userName Attribute** | Custom user attribute name, only if strategy = `attribute` | ❌ |
| **Deprovision Action** | What to do on delete or group removal: `deactivate` (PATCH `active=false`, default) or `delete` (`DELETE /Users/{id}`) | ✅ |
| **Lookup Strategy** | How to resolve SCIM user and group IDs: `externalId first` (default) or `name only` | ✅ |
| **Sync Groups** | Enable SCIM `/Groups` sync. Group create/rename/delete and membership changes are pushed to the SCIM target. Disabled by default. | ❌ |
| **Sync Groups Filter** | Comma-delimited list for group names to include, e.g. `admins,developers,team-engineering`. Leave blank to scope group sync to *Filter Group* only. | ❌ |
| **Use Regex for Group Filter** | Enable to use Java regex patterns for group filter, e.g. `admins\|developers\|team-.*`. | ❌ |
| **LDAP Users Provisioning Mode** | How LDAP-driven user sync runs on *Synchronize changed users*: `Delta` (default) or `Full` | ✅ |
| **LDAP Groups Provisioning Mode** | How LDAP-driven group sync runs on *Synchronize changed users*: `Delta (add members)` (default), `Delta (add and remove members)`, or `Full` | ✅ |
| **Group Member Remove Form** | SCIM PATCH format for removing a group member: `RFC 7644 path filter` (default) or `Non-RFC value array` | ✅ |

### Lookup Strategy

The **Lookup Strategy** applies to both `/Users` and `/Groups`:

- **`externalId first`** — Query by `externalId` first. If exactly one result is returned, use it. If no result or multiple results are returned, fall back to `userName` for users or `displayName` for groups.
- **`name only`** — Skip the `externalId` request and resolve users by `userName` and groups by `displayName`.

Use `name only` when the SCIM server ignores the `externalId` filter and returns an unfiltered list.

### Group Member Remove Form

When removing a member from a SCIM group, the plugin supports two payload formats:

- **`RFC 7644 path filter`** — The spec-compliant form:

  ```json
  {
    "op": "remove",
    "path": "members[value eq \"<id>\"]"
  }
  ```

- **`Non-RFC value array`** — A compatibility form for servers that require a `value` field on every operation:

  ```json
  {
    "op": "remove",
    "path": "members",
    "value": [
      {
        "value": "<id>"
      }
    ]
  }
  ```

---

## 🔄 Supported Events

| Event | Action |
| --- | --- |
| **REGISTER** | Create new SCIM user |
| **UPDATE_PROFILE / UPDATE_EMAIL** | Update SCIM user fields |
| **UPDATE_CREDENTIAL (password)** | Patch password if supported |
| **DELETE_ACCOUNT** | Deprovision SCIM user according to *Deprovision Action* |
| **Admin CREATE/UPDATE/DELETE** | Sync CRUD operations |
| **Group membership add/remove** | Provision or deprovision users based on group membership, if `Filter Group` is set; also updates the SCIM group member list when `Sync Groups` is enabled |
| **Group CREATE/UPDATE/DELETE** | Create, rename, or delete the corresponding SCIM group when `Sync Groups` is enabled |

> ℹ️ **Lifecycle lookup and deprovisioning:** users are matched by SCIM `externalId` (the Keycloak user id) first, falling back to `userName` for users provisioned before `externalId` existed. The `externalId` is also backfilled on update for legacy users. Deprovisioning defaults to **deactivate** (`PATCH active=false`); set *Deprovision Action* to `delete` for providers that require a hard delete, such as VMware vCenter.

---

## 🗂️ SCIM Group Sync

Group sync is **opt-in** and disabled by default to avoid affecting existing deployments on SCIM targets that do not support `/Groups`.

### How to enable

In the provider configuration (*User Federation → keycloak-scim-outbound*):

1. Toggle **Sync Groups** to `true`.
2. Optionally fill **Sync Groups Filter (regex)** with a Java regex pattern for the group names you want to sync, for example `admins|developers|team-.*`.
3. If the regex filter is blank, group sync is scoped to the group configured in **Filter Group**.
4. Choose the required LDAP provisioning modes and member removal form.
5. Save.

### What gets synced

| Source | Keycloak event or trigger | SCIM operation |
| --- | --- | --- |
| Admin / event-driven | Group created | `POST /Groups` — creates an empty group with `externalId` = Keycloak group UUID and `displayName` = group name |
| Admin / event-driven | Group renamed | `PATCH /Groups/{id}` — updates `displayName` |
| Admin / event-driven | Group deleted | `DELETE /Groups/{id}` — found by `externalId` |
| Admin / event-driven | User added to group | `PATCH /Groups/{id}` — adds the user as a member (`op: add`) |
| Admin / event-driven | User removed from group | `PATCH /Groups/{id}` — removes the member using the configured remove form |
| LDAP sync (delta) | User's group membership changed in LDAP | Create the group with `POST /Groups` if needed, then `PATCH /Groups/{id}` with an individual `add` or `remove` |
| LDAP sync (full) | *Synchronize all users* or `Full` mode | Create the group with `POST /Groups` if needed, then `PATCH /Groups/{id}` with a complete `replace` of the member list |
| Group leaves scope | Group deleted or no longer matches the configured scope filter | `DELETE /Groups/{id}` — the remote group is removed during the deprovision sweep |

Groups are matched in SCIM by `externalId` (Keycloak UUID) first, falling back to `displayName`. If a group is not found during LDAP delta or full sync, the plugin creates it with `POST /Groups`, using the Keycloak group UUID as `externalId` and the Keycloak group name as `displayName`. It then resolves the newly created group and continues with membership processing. The `externalId` is set at creation time, so renames do not break the link.

### Sync execution order

Each synchronization sweep runs in three steps:

1. **User sync** — Runs first so SCIM user IDs exist before group membership is resolved.
2. **Group sync** — Creates or resolves in-scope groups and applies membership changes. Runs only when **Sync Groups** is enabled.
3. **Group deprovision sweep** — Deletes remote SCIM groups whose corresponding Keycloak group no longer matches the configured scope. Runs after group sync, regardless of whether user and group provisioning use Delta or Full mode.

This means changing the **Sync Groups Filter (regex)** can remove remote groups from the previous scope on the next synchronization sweep. A group is deleted only after it is determined to be outside the current scope for that target.

### Provisioning modes

The **LDAP Users Provisioning Mode** and **LDAP Groups Provisioning Mode** settings control *Synchronize changed users*.

| Mode | `/Users` behavior | `/Groups` behavior |
| --- | --- | --- |
| **Delta** | Flush only users with pending `NEW_ADDED` or `NEW_DELETED` entries | Not applicable |
| **Delta (add members)** | Not applicable | Flush pending member additions only; member removals remain pending |
| **Delta (add and remove members)** | Not applicable | Flush pending additions and removals, then cross-check the remote member list |
| **Full** | Re-provision every current member of *Filter Group* and deprovision users who left | Create or resolve every in-scope group and send a complete `PATCH replace` of its member list |

*Synchronize all users* always runs full mode regardless of these settings. *Synchronize changed users* uses the configured mode.

The `Delta (add and remove members)` mode performs an additional cross-check after flushing pending changes. Members that still exist remotely but are no longer present in the local Keycloak group are removed from the SCIM group. Keycloak remains the source of truth; the cross-check does not add missing members or create groups.

### Provisioning scope

- **User provisioning** is scoped to members of *Filter Group*.
- **Event-driven group sync** applies to groups matching the *Sync Groups Filter* regex, or to *Filter Group* when the filter is blank.
- **LDAP-driven group sync** applies the same regex or blank-filter rule.
- Only users within the *Filter Group* provisioning scope are included when building a group member list.
- Membership updates in SCIM only apply to users that already have a SCIM ID. Users that were never provisioned to the SCIM target are skipped.
- LDAP-driven group creation is performed only for groups in scope for the configured target.
- Remote groups that leave the current scope are deleted by the deprovision sweep, including groups affected by a changed scope filter.

### Limitations

- **No retroactive processing without a sync:** enabling *Sync Groups* does not itself run a sync. Run **Synchronize all users** on the SCIM outbound provider after enabling if existing LDAP groups and their current members should be sent immediately.
- **Out-of-scope cleanup requires a synchronization sweep:** a deleted group or a group that no longer matches the filter is removed remotely when the provider's synchronization sweep runs. It is not removed merely by changing the configuration.
- **LDAP group auto-provisioning requires a working `/Groups` endpoint:** LDAP delta and full sync create missing in-scope SCIM groups automatically. If `POST /Groups` fails, membership processing for that group is skipped and retried during a later sync.
- **Permissions are not assigned:** creating a group via SCIM does not automatically grant it any permissions in the target system. Permission assignment must be done manually in the target after the group is created.
- **Top-level groups only:** nested Keycloak sub-groups fire the same `GROUP` events and are synced as flat groups in SCIM. SCIM v2 Groups do not have a native hierarchy.
- **Target must support `/Groups`:** not all SCIM implementations expose the Groups resource. Check your target's documentation or `ServiceProviderConfig` before enabling.

---

## 🪵 Logging

All plugin logs are prefixed with:

```text
[keycloak-scim-outbound][<target>]
```

Example output:

```text
2025-09-30T18:09:56Z [keycloak-scim-outbound][SCIM Keycloak] UPDATE targetUserName=scim@domain.com realm=domain OK
```

Enable Keycloak's log level for debugging:

```bash
kc.sh start --log-level=org.keycloak.events=DEBUG,es.diegosr.keycloak_scim_outbound=DEBUG
```

At `DEBUG` level, the plugin can log:

- SCIM request and response details
- User and group ID lookup decisions
- Membership diff decisions
- LDAP user and group sync call sites
- Group cross-check decisions and removals
- Group auto-provisioning decisions and payloads
- Out-of-scope group deprovision decisions
- Requests and responses

---

## 🧪 Example targets

| Target | Base URL | Notes |
| --- | --- | --- |
| **Passbolt** | `https://your-passbolt-domain/scim/v2` | Works out of the box |
| **Nextcloud** | `https://cloud.example.com/apps/user_saml/scim/v2` | Requires SCIM app enabled |
| **Custom app** | Any compliant SCIM v2 endpoint | Supports `/Users` and `/Groups` resources |

---

## 🛠 Development

### Requirements

- Java 17+
- Maven 3.8+
- Keycloak 22+ (Quarkus distribution)

### Run in dev mode

```bash
kc.sh start-dev --spi-events-listener-keycloak-scim-outbound-enabled=true
```

---

## 🧩 Project structure

```text
keycloak-scim-outbound/
├── pom.xml
└── src/main/java/es/diegosr/keycloak_scim_outbound/
    ├── ScimEventListenerProvider.java
    ├── ScimEventListenerProviderFactory.java
    ├── http/ScimClient.java
    ├── ldapsync/GroupMembershipState.java
    ├── ldapsync/LdapSyncNotifierMapper.java
    ├── ldapsync/LdapSyncNotifierMapperFactory.java
    ├── ldapsync/MembershipState.java
    ├── ldapsync/ScimGroupSync.java
    ├── ldapsync/ScimMembershipSync.java
    ├── ui/ScimTargetProviderFactory.java
    ├── ui/ScimTargetProvider.java
    └── util/ScimMapper.java
```

---

## 🔌 Optional LDAP / Active Directory Integration

By default this plugin reacts to Keycloak events, including logins, admin actions, and direct group membership changes. If your users are managed in an **LDAP or Active Directory** directory and group membership is driven by LDAP sync rather than by Keycloak events, those membership changes are invisible to the event listener — and users will not be provisioned or deprovisioned automatically.

The `ldapsync` package adds a dedicated **LDAP Storage Mapper** (`LdapSyncNotifierMapper`) that bridges this gap. It is entirely optional; if you are not using LDAP/AD federation you do not need it.

### When is this mapper needed?

Add `LdapSyncNotifierMapper` when **all** of the following are true:

- You have an LDAP or Active Directory user federation provider configured in Keycloak.
- Group membership for your users is controlled in LDAP/AD, not manually in Keycloak.
- You want SCIM provisioning to react to LDAP-driven membership changes.
- You want LDAP-driven membership changes to update SCIM `/Groups`.

If group membership is managed directly in Keycloak, for example through the Admin Console or Admin API, the standard event listener already handles it and this mapper is not required.

### What does it do?

During every LDAP sync run, `LdapSyncNotifierMapper` compares each user's current group membership, as resolved from LDAP, against the last recorded state. When it detects a change it writes a pending marker to local Keycloak attributes:

- **For `/Users`** — a marker on the user's local Keycloak attributes (`MembershipState`), picked up by `ScimMembershipSync`.
- **For `/Groups`** — a marker on the relevant group's local Keycloak attributes (`GroupMembershipState`), picked up by `ScimGroupSync` when *Sync Groups* is enabled.

Both sets of markers are flushed the next time a sync sweep runs. The same sweep also performs the out-of-scope group cleanup when **Sync Groups** is enabled.

### Sync trigger

Pending membership changes and out-of-scope group cleanup are processed in two ways:

- **On demand** — clicking **Synchronize all users** or **Synchronize changed users** on the SCIM outbound provider in User Federation triggers an immediate sweep for that specific target.
- **Automatically** — configure a **Sync Interval** directly in the admin console under *User Federation → your SCIM provider → Sync Settings*. Keycloak's native sync scheduler calls the sweep at that interval. No separate background timer is required.

If a SCIM push fails, for example because the target is temporarily unreachable, the pending marker is left in place and the push is retried on the next sync. A failed group deletion is likewise retried during a later sweep.

### Provisioning modes

Both user sync and group sync support configurable modes:

| Mode | `/Users` behavior | `/Groups` behavior |
| --- | --- | --- |
| **Delta** | Flush only users with pending `NEW_ADDED` or `NEW_DELETED` entries | Flush pending member additions and removals according to the selected group mode |
| **Delta (add members)** | — | Flush pending member additions only |
| **Delta (add and remove members)** | — | Flush pending additions and removals, then cross-check remote membership |
| **Full** | Re-provision every current member of *Filter Group* and deprovision users who left | Create or resolve every in-scope group and send a complete `PATCH replace` of the full member list |

The group deprovision sweep runs after group synchronization for both Delta and Full modes. *Synchronize all users* always runs full mode. *Synchronize changed users* uses the configured provisioning modes.

### How to add LdapSyncNotifierMapper

1. Open the **Keycloak Admin Console**.
2. Go to **User Federation** and select your existing LDAP provider.
3. Open the **Mappers** tab and click **Add mapper**.
4. Set **Mapper Type** to `ldap-sync-notifier` and give it a name, for example `SCIM Notifier`.
5. Save.

### Mapper ordering — important

`LdapSyncNotifierMapper` **must be placed after the built-in `group-ldap-mapper`** in the mapper list. Keycloak runs mappers in order during a sync; the group mapper must have already resolved the user's group membership from LDAP before the notifier mapper inspects it.

To check or adjust the order, go to **User Federation → your LDAP provider → Mappers** and verify that `group-ldap-mapper` appears above `LdapSyncNotifierMapper` in the list.

---

## 📜 License

This project is distributed under the [LICENSE](LICENSE).

---

## 👤 Author

**Termindiego25**

[www.diegosr.es](https://www.diegosr.es)

---

> 💡 *If this project helps you, consider giving it a ⭐ on GitHub!*
