#!/usr/bin/env python3
# -*- coding: future_fusions -*-
"""
██████╗ ██╗   ██╗ ██████╗ ███╗   ███╗ █████╗ ██████╗ ██╗  ██╗
██╔══██╗██║   ██║██╔════╝ ████╗ ████║██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝██║   ██║██║  ███╗██╔████╔██║███████║██████╔╝ ╚███╔╝ 
██╔══██╗██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝  ██╔██╗ 
██████╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     ██╔╝ ██╗
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
"""
import os
import sys
import asyncio
import argparse
from rich.console import Console
from src.scanner import SubdomainHunter, DNSWarrior, PortAssassin
from src.ai_analyzer import NeuroAnalyzer
from src.tor_manager import TorManager
from src.encryption import CryptoVault
from configs import load_config
from utils.reporter import generate_report

console = Console()

async def main():
    parser = argparse.ArgumentParser(description="BugMapX v10.1 - AI-Powered Attack Surface Mapper")
    parser.add_argument("target", help="Domain or IP to scan")
    parser.add_argument("--tor", action="store_true", help="Enable Tor anonymity")
    parser.add_argument("--ai", choices=["light", "medium", "heavy"], default="medium", help="AI model size")
    parser.add_argument("--output", choices=["console", "json", "html", "encrypted"], default="console", help="Report format")
    parser.add_argument("--aggression", type=int, choices=range(1, 11), default=5, help="Scan intensity (1-10)")
    args = parser.parse_args()

    config = load_config()
    config['tor']['enabled'] = args.tor or config['tor']['enabled']
    config['ai']['model'] = args.ai
    config['scan']['aggression'] = args.aggression

    console.print(f"[bold green]Starting BugMapX scan on [yellow]{args.target}[/yellow][/bold green]")
    console.print(f"Mode: [cyan]{'STEALTH' if config['tor']['enabled'] else 'CLEARNET'}[/cyan] | AI: [cyan]{args.ai.upper()}[/cyan] | Aggression: [cyan]{args.aggression}/10[/cyan]")
    
    # Initialize components
    dns = DNSWarrior()
    hunter = SubdomainHunter(args.target, config)
    ai = NeuroAnalyzer(config['ai']['model'])
    crypto = CryptoVault()

    # Scan execution
    results = {}
    try:
        if config['tor']['enabled']:
            async with TorManager(config['tor']['password']) as tor:
                results = await execute_scan(args.target, hunter, dns, ai, tor, config)
        else:
            results = await execute_scan(args.target, hunter, dns, ai, None, config)
    except KeyboardInterrupt:
        console.print("[red]Operation aborted by user![/red]")
        sys.exit(1)
    
    # Generate report
    generate_report(results, args.output, crypto)
    console.print(f"[bold green]Scan completed! Report saved as [yellow]{args.output}[/yellow][/bold green]")

if __name__ == "__main__":
    asyncio.run(main())
