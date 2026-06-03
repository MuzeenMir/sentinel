package sentinel.detections

import rego.v1

# sentinel:detection_id=sentinel.python.large_outbound_upload
large_outbound_upload := finding if {
	input.event_type == "network"
	input["network.direction"] == "outbound"
	bytes_out := input["network.bytes_out"]
	bytes_out >= 500000000
	finding := {
		"detection_id": "sentinel.python.large_outbound_upload",
		"title": "Large outbound upload",
		"severity": "medium",
		"message": "Outbound transfer exceeded 500000000 bytes",
		"metadata": {"bytes_out": bytes_out},
	}
}

# sentinel:detection_id=sentinel.python.suspicious_powershell
suspicious_powershell := finding if {
	command_line := input.command_line
	powershell_process
	encoded_powershell_command
	finding := {
		"detection_id": "sentinel.python.suspicious_powershell",
		"title": "Suspicious PowerShell execution",
		"severity": "high",
		"message": sprintf("PowerShell used EncodedCommand: %s", [command_line]),
		"metadata": {"technique": "T1059.001"},
	}
}

powershell_process if {
	contains(lower(input.process_name), "powershell")
}

powershell_process if {
	contains(lower(input.process_name), "pwsh")
}

encoded_powershell_command if {
	contains(lower(input.command_line), "-encodedcommand")
}

encoded_powershell_command if {
	contains(lower(input.command_line), " -enc ")
}

findings contains finding if {
	finding := large_outbound_upload
}

findings contains finding if {
	finding := suspicious_powershell
}
