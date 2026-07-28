def lambda_handler(event, context):

    controls = load_controls()

    evidence = collect_evidence()

    findings = validate_controls(
        controls,
        evidence
    )

    report = generate_compliance_report(findings)

    upload_report(report)

    return success
