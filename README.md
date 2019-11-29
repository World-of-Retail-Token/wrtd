![WRT](docs/images/logo.png)

# What is WRT?
WRT is a network of computers which use the [Ripple consensus algorithm](https://www.youtube.com/watch?v=pj1QVb1vlC0) to atomically settle and record
transactions on a secure distributed database, the WRT Consensus Ledger
(WCL). Because of its distributed nature, the WCL offers transaction immutability
without a central operator. The WCL contains a built-in currency exchange and its
path-finding algorithm finds competitive exchange rates across order books
and currency pairs.

### Key Features
- **Distributed**
  - Direct account-to-account settlement with no central operator
  - Decentralized global market for competitive FX
- **Secure**
  - Transactions are cryptographically signed using ECDSA
  - Multi-signing capabilities
- **Scalable**
  - Capacity to process the world’s cross-border payments volume
  - Easy access to liquidity through a competitive FX marketplace

### License
`wrtd` is open source and permissively licensed under the
ISC license. See the LICENSE file for more details.

#### Repository Contents

| Folder  | Contents |
|---------|----------|
| ./build | Intermediate and final build outputs.          |
| ./Builds| Platform or IDE-specific project files.        |
| ./conf  | Example configuration files.                   |
| ./doc   | Documentation.                                 |
| ./src   | Source code.                                   |

Some of the directories under `src` are external repositories inlined via
git-subtree. See the corresponding README for more details.

- - -

Copyright © 2017-2019, Ripple Labs. All rights reserved.

Copyright © 2019, WORLD OF RETAIL SERVICES LIMITED. All rights reserved.

Portions of this document, including but not limited to the Ripple logo,
images and image templates are the property of Ripple Labs and cannot be
copied or used without permission.
