# EDA: Give AI agents access to the right data, under the right person's authority

AI agents can help people find information, analyze records and complete tasks. To do that safely, an organization needs to control which data an agent can access—and know who authorized its work.

**EDA is being built to provide that control.**

It sits between AI agents and the organization's data sources. Before information is returned, EDA would check which agent is asking, which person assigned the task, and what that agent is permitted to do on the person's behalf.

The agent has its own identity for accountability. The person provides the delegated authority. A task can narrow that authority, but it cannot give the agent more access than the person currently has. There is no intended autonomous, agent-only authority path.

> This page describes the intended product experience. The current sandbox demonstrates parts of the foundation; the complete agent workflow is still being built. See [what works today](#what-works-today-and-what-is-still-being-built).

## The value for an organization

EDA's purpose is to make useful agent access possible without handing each agent broad credentials to company systems.

It would give organizations:

- **Control:** Limit access to the information and actions needed for a task.
- **Accountability:** Record which agent acted, for whom, and under which authorization.
- **Consistency:** Give agents a common way to request information from different systems.
- **Visibility:** Explain the relationships and evidence supporting an access decision.
- **Ownership:** Run the control layer within the organization's chosen environment.

The goal is not to copy all company data into a new central repository. EDA builds a map of identities, resources and relationships. Data remains in its source system until an authorized request requires it.

## How an organization would set it up

### 1. Connect the organization's identity system

Start by connecting EDA to the system the organization uses to manage people and groups, such as Microsoft Entra ID.

This lets EDA recognize a person and understand relevant group relationships. Each agent would also have a registered identity, linked to the person who authorized its task through a time-limited delegation.

For an organization using traditional Active Directory, the connection would depend on its identity setup—for example, an existing synchronization with Entra or a dedicated directory connector.

### 2. Choose where EDA runs

EDA would run as a container: a packaged application that the organization can host in its own environment.

That could be on a local server, in an on-premises environment, or in its cloud account. A database alongside EDA stores the relationship map, synchronization state and audit evidence.

The organization chooses where that control information lives and who can administer it.

### 3. Connect the data sources

The organization adds a connector for each supported data source, such as a database, document store or cloud storage service.

The SDK is the toolkit used to build those connectors. It gives each connector a consistent way to describe what exists, report relevant relationships and, as authorized retrieval is implemented, return permitted information.

An existing connector reduces the integration work. A new type of data store needs a connector that understands that system's particular access rules. The SDK makes the platform extensible; it does not automatically understand every system.

### 4. Define the boundaries

The organization decides which agents may work with which systems, what tasks they may perform, and when additional approval is required.

EDA would apply those restrictions alongside the person's current access, the task's delegated scope and the source system's own permissions.

A person having access to an entire department's data would not mean every agent task receives that same broad access.

### 5. Keep the map current

Connectors refresh the information EDA uses to make decisions.

When group memberships, permissions or resources change, the map must reflect those changes. Evidence that is missing, unsupported or too old must not silently become permission to access data.

## Example: an agent prepares a customer summary

A sales manager asks an agent:

> "Summarize the recent orders and support issues for Customer A."

The intended workflow would be:

**1. The agent submits the request.**

It identifies itself, the manager who assigned the task, and the authorization linking it to that task.

**2. EDA verifies both identities and the delegation.**

It checks that the request comes from the registered agent, that the manager authorized it, and that the authorization has not expired or been revoked.

**3. EDA identifies the relevant sources.**

Its resource map helps locate the customer's order information and support records. Finding a source does not itself grant access to its contents.

**4. EDA checks the permitted scope.**

It determines whether the manager can access those records, whether the agent's task includes them, and whether organizational or source-system restrictions apply.

For example, the task might permit order dates and support summaries while excluding payment details and restricted internal notes.

**5. The connectors retrieve the permitted information.**

EDA requests only the approved scope using the supported source controls. Fields, records or documents outside that scope are excluded before information reaches the agent.

If EDA cannot establish that access is permitted, it refuses that portion of the request or follows a defined approval process.

**6. EDA records the decision and retrieval.**

The evidence identifies the agent, the manager, the requested operation, the sources involved and the outcome. Audit records should avoid unnecessarily copying sensitive data.

**7. The agent receives the approved data and prepares the answer.**

The agent can summarize what it received and identify any limitations. It does not receive general-purpose credentials to explore beyond the task.

If the manager loses access or revokes the delegation, subsequent requests should be refused once that change is recognized. Previously delivered information cannot be recalled, which makes narrow access and timely synchronization important.

## What works today and what is still being built

The current EDA sandbox has demonstrated live Entra and AWS metadata collection, relationship storage, supported identity and access checks, audit verification, and preservation of inventory through local service restarts.

The complete agent workflow above is the intended product direction. The required agent-and-user identity pairing, bounded task delegation, authorized data retrieval and comprehensive source-specific permission evaluation still need implementation.

The Entra connector exists today. A direct traditional Active Directory connector and a complete production cloud deployment are not yet provided.

**The promise is straightforward: an agent should receive only the data it needs, under the authority of the person who tasked it, with evidence of how that access was granted.**

## Explore further

- [Project overview and repository guide](README.md)
- [Installation guide and setup order](INSTALL.md)
- [How to use and test the sandbox](docs/USAGE.md)
- [Current capabilities and limitations](docs/IMPLEMENTATION_STATUS.md)
- [Sanitized live test summary](docs/LIVE_TEST_SUMMARY.md)
- [Implementation roadmap](PRODUCTION_ROADMAP.md)
