"""talonctl validate-query — validate a single LogScale/NGSIEM query."""

import click

from talonctl.commands._common import console


@click.command("validate_query")
@click.option("--query", "-q", type=str, help="Query string to validate (use quotes)")
@click.option("--file", "-f", "query_file", type=str, help="Path to file containing query")
@click.option(
    "--template", "-t", type=str, help="Path to YAML template (extracts search.filter, search.query, or queryString)"
)
@click.pass_context
def validate_query(ctx, query, query_file, template):
    """Validate a single LogScale/NGSIEM query."""
    import yaml
    from pathlib import Path

    # Determine query source
    resolved_query = None

    if query:
        resolved_query = query
    elif query_file:
        file_path = Path(query_file)
        if not file_path.exists():
            console.print(f"INVALID: File not found: {query_file}")
            raise SystemExit(1)
            return
        resolved_query = file_path.read_text()
    elif template:
        template_path = Path(template)
        if not template_path.exists():
            console.print(f"INVALID: Template not found: {template}")
            raise SystemExit(1)
            return
        try:
            with open(template_path) as f:
                template_data = yaml.safe_load(f)
            search = template_data.get("search", {})
            resolved_query = search.get("filter") or search.get("query")
            if not resolved_query:
                resolved_query = template_data.get("queryString")
            if not resolved_query:
                console.print("INVALID: No search.filter, search.query, or queryString found in template")
                raise SystemExit(1)
                return
        except yaml.YAMLError as e:
            console.print(f"INVALID: YAML parse error: {e}")
            raise SystemExit(1)
            return
    else:
        console.print("INVALID: Must specify --query, --file, or --template")
        raise SystemExit(1)
        return

    # Initialize NGSIEM client and validate
    try:
        from talonctl.utils.ngsiem_client import NGSIEMClient

        ngsiem_client = NGSIEMClient()
        result = ngsiem_client.test_query_syntax(resolved_query)

        if result["valid"]:
            console.print("VALID")
        else:
            console.print(f"INVALID: {result['message']}")
            raise SystemExit(1)

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"INVALID: {e}")
        raise SystemExit(1)
