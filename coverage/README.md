# ATT&CK Coverage

This folder contains an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer file tracking which techniques have detections in this repository.

---

## Files

| File | Description |
|---|---|
| `layer.json` | ATT&CK Navigator layer — import at navigator.attack.mitre.org |

---

## How to Use the Navigator Layer

1. Go to [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)
2. Click **Open Existing Layer** → **Upload from local**
3. Select `coverage/layer.json`
4. The Navigator will display which techniques are covered, colour-coded by status:
   - **Green (score 2)**: Stable detection — validated in lab
   - **Yellow (score 1)**: Experimental — rule exists but not fully validated
   - **No highlight**: No detection

---

## Current Coverage

> Update this table whenever `layer.json` is updated.

| Tactic | Technique | Sub-technique | Name | Status |
|---|---|---|---|---|
| Persistence | T1547 | .001 | Registry Run Keys / Startup Folder | Stable |

---

## Updating the Layer

When you add or promote a detection:

1. Open `layer.json` in a text editor.
2. Find the `techniques` array.
3. Add or update the entry for the technique ID.
4. Update the `comment` field with a brief note and the rule file path.
5. Commit the updated layer alongside the detection.

Example entry:
```json
{
  "techniqueID": "T1547.001",
  "score": 2,
  "comment": "Stable — rule.yml validated via Atomic Red Team Test 1. See detections/persistence/T1547.001-registry-run-keys/",
  "enabled": true
}
```

---

## Coverage Screenshot

> Replace this placeholder with an exported PNG from ATT&CK Navigator once you have enough techniques to make the visualisation meaningful.

`[ATT&CK Navigator screenshot — pending]`
