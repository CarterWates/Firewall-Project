from firewall_monitor.monitoring.events import parse_firewall_log_line


def test_parse_firewall_monitor_log_line() -> None:
    event = parse_firewall_log_line(
        "firewall-monitor block-telnet: IN=eth0 OUT= "
        "SRC=203.0.113.10 DST=192.0.2.20 PROTO=TCP DPT=23"
    )

    assert event is not None
    assert event.rule_name == "block-telnet"
    assert event.action == "blocked"
    assert event.source_ip == "203.0.113.10"
    assert event.destination_ip == "192.0.2.20"
    assert event.protocol == "tcp"
    assert event.destination_port == 23
    assert event.input_interface == "eth0"


def test_parser_ignores_unrelated_log_line() -> None:
    event = parse_firewall_log_line("kernel: ordinary message")

    assert event is None


def test_parser_ignores_line_missing_required_fields() -> None:
    event = parse_firewall_log_line("firewall-monitor block-web: SRC=203.0.113.10")

    assert event is None
