"""
Security Agent CLI entry point.

Usage:
    python -m security_agent [--interactive]
    python -m security_agent analyze <config.json> [--output text|json] [--frameworks CIS,NIST]
    python -m security_agent cis list [--level 1|2] [--category <cat>]
    python -m security_agent cis get <ID>
    python -m security_agent cis search <keyword>
    python -m security_agent nist list [--family <fam>] [--baseline LOW|MODERATE|HIGH]
    python -m security_agent nist get <ID>
    python -m security_agent nist search <keyword>
"""

import sys


def main() -> None:
    from security_agent.agent import SecurityAgent

    agent = SecurityAgent()

    if len(sys.argv) <= 1 or sys.argv[1] == "--interactive":
        agent.run()
    else:
        command = " ".join(sys.argv[1:])
        result = agent.chat(command)
        print(result)


if __name__ == "__main__":
    main()
