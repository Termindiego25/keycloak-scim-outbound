# 🔐 Keycloak SCIM Outbound Plugin

A lightweight **Keycloak extension** that provisions users and groups to external applications via the **SCIM v2** protocol.

This plugin allows Keycloak to **push user lifecycle changes** (create, update, delete, deactivate) to external systems like **Passbolt**, **Nextcloud**, or any other SCIM-compliant service — all configurable directly from the **Keycloak Admin Console**.

---

## 🚀 Features

- 🔁 **Automatic user provisioning** — Create, update, or deactivate users in external SCIM targets.
- 👥 **Group-based filtering** — Provision only members of a specific Keycloak group.
- ⚙️ **UI configuration** — Configure endpoints, tokens, and mapping directly from *User Federation*.
- 🧩 **Customizable userName strategy**
  - `username` → use Keycloak username
  - `email` → use user’s email as SCIM `userName`
  - `attribute` → use a custom Keycloak user attribute
- 🧱 **SCIM v2 compatible** — Works with `/Users`, `/Groups`, and `/ServiceProviderConfig` endpoints.
- 🔒 **Token-based authentication (Bearer)** — no password sync required.

---

## 🧰 Installation

### 1. Build the plugin
```bash
mvn clean package
````

This generates a `.jar` under:

```
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

1. Open the **Keycloak Admin Console**
2. Go to **User Federation → Add provider → keycloak-scim-outbound**
3. Fill in the following fields:

| Field                       | Description                                                           | Required |
| --------------------------- | --------------------------------------------------------------------- | -------- |
| **SCIM Base URL**           | Base endpoint of your SCIM API, e.g. `https://app.example.com/scim/v2` | ✅        |
| **SCIM Token**              | Bearer token for authenticating with the SCIM target                  | ✅        |
| **Filter Group (optional)** | Only users in this group will be provisioned                          | ❌        |
| **userName Strategy**       | How to build SCIM `userName` (`username`, `email`, or `attribute`)    | ✅        |
| **userName Attribute**      | Custom user attribute name (only if strategy = `attribute`)           | ❌        |
| **Deprovision Action**      | What to do on delete / group removal: `deactivate` (PATCH `active=false`, default) or `delete` (`DELETE /Users/{id}`) | ✅        |

---

## 🔄 Supported Events

| Event                             | Action                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------- |
| **REGISTER**                      | Create new SCIM user                                                            |
| **UPDATE_PROFILE / UPDATE_EMAIL** | Update SCIM user fields                                                         |
| **UPDATE_CREDENTIAL (password)**  | Patch password if supported                                                     |
| **DELETE_ACCOUNT**                | Deprovision SCIM user (deactivate or delete, per *Deprovision Action*)          |
| **Admin CREATE/UPDATE/DELETE**    | Sync CRUD operations                                                            |
| **Group membership add/remove**   | Provision/deprovision users based on group membership (if `filterGroup` is set) |

> ℹ️ **Lifecycle lookup & deprovisioning:** users are matched by SCIM `externalId` (the Keycloak user id) first, falling back to `userName` for users provisioned before `externalId` existed. The `externalId` is also backfilled on update for legacy users. Deprovisioning defaults to **deactivate** (`PATCH active=false`); set *Deprovision Action* to `delete` for providers that require a hard delete (e.g. VMware vCenter).

---

## 🪵 Logging

All plugin logs are prefixed with:

```
[keycloak-scim-outbound][<component>]
```

Example output:

```
2025-09-30T18:09:56Z [keycloak-scim-outbound][SCIM Keycloak] UPDATE targetUserName=scim@domain.com realm=domain OK
```

Enable Keycloak’s log level for debugging (optional):

```bash
kc.sh start --log-level=org.keycloak.events=DEBUG,es.diegosr.keycloak_scim_outbound=DEBUG
```

---

## 🧪 Example targets

| Target         | Base URL                                           | Notes                      |
| -------------- | -------------------------------------------------- | -------------------------- |
| **Passbolt**   | `https://your-passbolt-domain/scim/v2`             | Works out of the box       |
| **Nextcloud**  | `https://cloud.example.com/apps/user_saml/scim/v2` | Requires SCIM app enabled  |
| **Custom app** | Any compliant SCIM v2 endpoint                     | Supports `/Users` resource |

---

## 🛠 Development

### Requirements

* Java 17+
* Maven 3.8+
* Keycloak 22+ (Quarkus distribution)

### Run in dev mode

```bash
kc.sh start-dev --spi-events-listener-keycloak-scim-outbound-enabled=true
```

---

## 🧩 Project structure

```
keycloak-scim-outbound/
├── pom.xml
└── src/main/java/es/diegosr/keycloak_scim_outbound/
    ├── ScimEventListenerProvider.java
    ├── ScimEventListenerProviderFactory.java
    ├── http/ScimClient.java
    ├── ui/ScimTargetProviderFactory.java
    ├── ui/ScimTargetProvider.java
    └── util/ScimMapper.java
```

---

## 📜 License

This project is distributed under the [LICENSE](LICENSE).

---

## 👤 Author

**Termindiego25**
[www.diegosr.es](https://www.diegosr.es)

---

> 💡 *If this project helps you, consider giving it a ⭐ on GitHub!*
