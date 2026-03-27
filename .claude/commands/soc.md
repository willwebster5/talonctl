<command name="soc">
    <description>SOC operations: $ARGUMENTS</description>

    <rules priority="critical">
        <rule>Always invoke the soc skill for processing</rule>
        <rule>Never modify detection templates without explicit user approval</rule>
        <rule>Update .claude/skills/soc/memory/ files after every triage session per the Living Documents protocol</rule>
        <rule>Suggest environmental-context.md updates when new context is discovered during investigation</rule>
        <rule>Follow the principle of least filtered — FP is always better than a missed TP</rule>
    </rules>

    <actions>
        <action trigger="starts-with:triage">
            Triage the alert. Follow the soc skill workflow.
        </action>

        <action trigger="starts-with:daily">
            Review today's untriaged alerts. Follow the soc skill daily mode workflow.
        </action>

        <action trigger="starts-with:tune">
            Tune the specified detection. Follow the soc skill tuning workflow.
        </action>

        <action trigger="starts-with:hunt">
            Hunt for threats. Follow the soc skill hunt mode workflow.
        </action>

        <action trigger="default">
            Show available subcommands:

            /soc triage &lt;alert-url-or-id&gt;  — Triage a specific alert (full lifecycle)
            /soc daily [product]              — Review today's untriaged alerts (product: endpoint, ngsiem, identity, cloud_security)
            /soc tune &lt;detection-name&gt;       — Tune a detection (skip triage)
            /soc hunt &lt;description-or-IOCs&gt;  — Threat hunting mode
        </action>
    </actions>
</command>
