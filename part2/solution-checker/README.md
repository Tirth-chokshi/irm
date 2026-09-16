# solution-checker — do not open until you have investigated the log yourself

This folder contains an automated analyser that answers all eight assignment
questions from `sysmon-events.json`. It is quarantined here on purpose.

**Use it only as a second opinion, after your own investigation.**

The method guide you should work from is `../README.md`. It maps each question
to a Sysmon Event ID and a field, and stops there deliberately.

## When you are ready to check your work

```bash
cd part2/solution-checker
# edit LOG_FILE at the top of sysmon_analysis.py to point at your log
python3 sysmon_analysis.py
```

Outputs land in `output/`:

| File | Contents |
|---|---|
| `investigation_report.txt` | The eight questions, the method used, the candidate answer |
| `evidence_qN.txt` | The raw events behind each answer — read these, not just the answer |
| `event_id_summary.txt` | Count of each Event ID |
| `process_tree.txt` | Parent → child tree rebuilt from ProcessGuid |

The answers are **candidates from keyword matching, not proof.** If the script
disagrees with you, do not assume it is right — open the evidence file and
decide from the events. A novel technique will not match its keyword lists.

`test/` holds two synthetic fixtures (the same 22-event attack chain in two
different JSON layouts) used to verify the tooling. That data is invented and
has nothing to do with your assignment log.
