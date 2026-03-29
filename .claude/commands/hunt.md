<command name="hunt">
    <description>Threat hunting: $ARGUMENTS</description>

    <rules priority="critical">
        <rule>Always invoke the threat-hunting skill for processing</rule>
        <rule>Update .claude/skills/threat-hunting/memory/ files after every completed hunt per the Living Documents protocol</rule>
        <rule>Escalate immediately on confirmed active compromise — create case, handoff doc, surface to human</rule>
        <rule>Produce all three outputs (hunt report, detection backlog, gap report) in the Act phase</rule>
        <rule>Never modify detection templates directly — produce handoff docs for authoring skills</rule>
    </rules>

    <actions>
        <action trigger="starts-with:hypothesis">
            Run a hypothesis-driven threat hunt. Follow the threat-hunting skill PEAK workflow (Prepare → Execute → Act).
        </action>

        <action trigger="starts-with:intel">
            Run an intelligence-driven threat hunt. Follow the threat-hunting skill PEAK workflow (Prepare → Execute → Act).
        </action>

        <action trigger="starts-with:baseline">
            Run a baseline/anomaly threat hunt. Follow the threat-hunting skill PEAK workflow (Prepare → Execute → Act).
        </action>

        <action trigger="starts-with:log">
            Display the hunt log. Read and summarize .claude/skills/threat-hunting/memory/hunt-log.md.
        </action>

        <action trigger="starts-with:coverage">
            Display the ATT&amp;CK coverage map. Read .claude/skills/threat-hunting/memory/coverage-map.md and cross-reference with resources/detections/.
        </action>

        <action trigger="default">
            No hunt type specified. Read the coverage map and suggest high-value hunt targets.
            If no arguments at all, follow the /hunt (no arguments) utility mode in the threat-hunting skill.
            If arguments don't match a known subcommand, treat as a hypothesis and route to hypothesis-driven hunting.
        </action>
    </actions>
</command>
