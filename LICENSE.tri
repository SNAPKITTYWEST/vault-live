TRI-LICENSE STRUCTURE
=====================

This project is available under THREE licensing options:

1. Business Source License 1.1 (BSL-1.1)
   - Source-available with commercial restrictions
   - No managed service offerings at enterprise scale
   - Converts to AGPL-3.0 after transition period (Change Date: 2028-08-08)
   - Full text: LICENSE.BSL

2. GNU Affero General Public License v3.0 (AGPL-3.0)
   - Strong network copyleft
   - SaaS/network distribution triggers source disclosure
   - All modifications must be AGPL-3.0
   - Full text: LICENSE.AGPL

3. Mozilla Public License 2.0 (MPL-2.0) + Commercial Dual License
   - Weak copyleft (file-level)
   - Can combine with proprietary code
   - Modified files must remain MPL-2.0
   - Commercial license available for copyleft bypass
   - Full text: LICENSE.MPL

================================================================================

WHICH LICENSE APPLIES TO MY USE CASE?

├─ Deploying as managed service / SaaS wrapper?
│  └─> AGPL-3.0 (network copyleft triggers disclosure)
│
├─ Enterprise scale without managed service?
│  └─> BSL-1.1 (source-available, restricted commercial use)
│
├─ Modifying specific files only?
│  └─> MPL-2.0 (file-level copyleft)
│
├─ Want to bypass copyleft restrictions?
│  └─> Commercial License (contact: ahmedparr93@gmail.com)
│
└─ Open source contribution / redistribution?
   └─> AGPL-3.0 (default copyleft path)

================================================================================

COPYRIGHT HOLDER

Copyright (C) 2026 Ahmad Ali Parr
Bel Esprit D'Accord Irrevocable Trust
SnapKitty Collective Limited (FLP)

Contact: ahmedparr93@gmail.com
Web: https://github.com/SNAPKITTYWEST

================================================================================

LICENSE COMPATIBILITY ENGINE

This project includes a Prolog-based license compatibility reasoner:
  backends/license_policy.pl

Query compatibility:
  swipl -q -t halt -f backends/license_policy.pl -- matrix

Check dependencies:
  swipl -q -t halt -f backends/license_policy.pl -- check agpl3 deps.json

Select license for use case:
  swipl -q -t halt -f backends/license_policy.pl -- select saas_wrapper

================================================================================

WHY TRI-LICENSE?

1. BSL Layer: Protects commercial interests while keeping code source-available.
   Prevents hyperscaler cloud vendors from offering managed services without
   contributing back. Converts to AGPL after transition period.

2. AGPL Layer: Ensures network copyleft. Anyone wrapping this in a SaaS product
   or exposing it over a network API must open-source their entire stack under
   the same terms. Strongest copyleft available.

3. MPL + Dual License Layer: Provides flexibility for enterprises that want to
   use specific components without full copyleft infection. File-level copyleft
   allows combining with proprietary code. Commercial license available to
   bypass all copyleft restrictions.

This structure mirrors Mozilla's historic tri-licensing strategy (MPL/GPL/LGPL)
adapted for modern SaaS/cloud distribution models.

================================================================================

TRANSITION TIMELINE

  2026-08-08: BSL-1.1 + AGPL-3.0 + MPL-2.0 tri-license effective
  2028-08-08: BSL converts to AGPL-3.0 (Change Date)
  2028-08-08+: Code available under AGPL-3.0 or MPL-2.0 or Commercial

After the Change Date, the BSL restriction is lifted and code becomes available
under AGPL-3.0 for all use cases (or MPL-2.0 for file-level use, or Commercial
for copyleft bypass).
