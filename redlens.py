#!/usr/bin/env python3
"""
Redlens - Professional Web Application Security Scanner
Created by Monish Kanna
GitHub: https://github.com/TENETx0/Redlens
"""

import sys
import signal
import subprocess
import socket
import requests
from urllib.parse import urlparse
from colorama import Fore, Style, Back, init
import time
import random
from datetime import datetime

# Initialize colorama for cross-platform color support
init(autoreset=True)

class AnimatedBanner:
    """Animated ASCII art banner with effects"""
    
    @staticmethod
    def animated_stars():
        """Display animated stars with trail effect"""
        stars = ['✦', '✧', '★', '☆', '✵', '✶', '✷', '✸', '✹', '✺']
        width = 70
        height = 8
        
        # Create multiple star positions (spectacular amount - 30 stars)
        star_positions = []
        for _ in range(30):
            star_positions.append({
                'x': random.randint(0, width - 1),
                'y': random.randint(0, height - 1),
                'char': random.choice(stars),
                'color': random.choice([Fore.YELLOW, Fore.CYAN, Fore.MAGENTA, Fore.WHITE])
            })
        
        # Animate stars appearing and twinkling
        for frame in range(20):
            output = [[' ' for _ in range(width)] for _ in range(height)]
            
            # Add stars with fade-in effect
            visible_stars = int((frame / 20) * len(star_positions))
            for i, star in enumerate(star_positions[:visible_stars]):
                y, x = star['y'], star['x']
                if 0 <= y < height and 0 <= x < width:
                    # Twinkle effect
                    if frame % 2 == 0 or i < visible_stars - 3:
                        output[y][x] = f"{star['color']}{star['char']}{Style.RESET_ALL}"
            
            # Print frame
            for line in output:
                print(''.join(line))
            
            time.sleep(0.15)
            
            # Clear screen for next frame
            if frame < 19:
                print('\033[8A')  # Move cursor up
        
        print()
    
    @staticmethod
    def typewriter_effect(text, delay=0.05):
        """Typewriter effect for text"""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()
    
    @staticmethod
    def gradient_text(text, colors):
        """Create gradient colored text"""
        if len(colors) < 2:
            return text
        
        result = ""
        length = len(text)
        step = length / (len(colors) - 1)
        
        for i, char in enumerate(text):
            if char == ' ':
                result += char
            else:
                color_index = min(int(i / step), len(colors) - 2)
                result += f"{colors[color_index]}{char}{Style.RESET_ALL}"
        
        return result
    
    @staticmethod
    def wave_animation(text, width=70):
        """Create a wave animation effect"""
        frames = 10
        for frame in range(frames):
            output = ""
            for i, char in enumerate(text):
                offset = int(3 * abs(((i + frame * 2) % 20) - 10) / 10)
                output += " " * offset + char + " " * (3 - offset)
            
            # Center the output
            padding = (width - len(output.replace(Fore.CYAN, '').replace(Style.RESET_ALL, ''))) // 2
            print(" " * max(0, padding) + output)
            
            if frame < frames - 1:
                time.sleep(0.1)
                print('\033[1A')  # Move cursor up

class RedlenseMenu:
    def __init__(self):
        self.running = True
        self.target_url = None
        self.scan_count = 0
        self.setup_signal_handlers()
        self.version = "v1.0.1"
        self.banner_shown = False
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful interruption"""
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C interruption"""
        print(f"\n\n{Fore.YELLOW}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Scan suspended. Type 'menu' to return or 'exit' to quit{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'═' * 70}{Style.RESET_ALL}")
        self.prompt_return()
    
    def prompt_return(self):
        """Prompt user after suspension"""
        while True:
            try:
                user_input = input(f"\n{Fore.CYAN}┌─[{Fore.WHITE}redlense{Fore.CYAN}]─[{Fore.YELLOW}suspended{Fore.CYAN}]\n└──╼ {Fore.WHITE}$ {Style.RESET_ALL}").strip().lower()
                if user_input == 'menu':
                    self.clear_screen()
                    self.display_banner()
                    self.display_menu()
                    break
                elif user_input == 'exit':
                    self.exit_program()
                else:
                    print(f"{Fore.RED}[!] Invalid command. Type 'menu' or 'exit'{Style.RESET_ALL}")
            except EOFError:
                self.exit_program()
    
    def clear_screen(self):
        """Clear the terminal screen"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_separator(self, char='═', length=70, color=Fore.CYAN):
        """Print a fancy separator"""
        print(f"{color}{char * length}{Style.RESET_ALL}")
    
    def animated_loading(self, text, duration=2.0):
        """Show animated loading with smooth animation"""
        frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for frame in frames:
                print(f"\r{Fore.CYAN}[{frame}] {text}...{Style.RESET_ALL}", end='', flush=True)
                time.sleep(0.15)  # Slower animation
                if time.time() >= end_time:
                    break
        
        print(f"\r{Fore.GREEN}[✓] {text}... Done!{Style.RESET_ALL}" + " " * 20)
    
    def progress_bar_animation(self, duration=2.0):
        """Animated progress bar"""
        steps = 50
        for i in range(steps + 1):
            filled = int(i)
            bar = '█' * filled + '░' * (steps - filled)
            percentage = (i / steps) * 100
            print(f"\r{Fore.CYAN}[{bar}] {percentage:.0f}%{Style.RESET_ALL}", end='', flush=True)
            time.sleep(duration / steps)
        print()
    
    def get_target_url(self):
        """Get and validate target URL from user"""
        while True:
            try:
                self.print_separator('─')
                print(f"\n{Fore.YELLOW}┌─[{Fore.CYAN}Target Configuration{Fore.YELLOW}]")
                print(f"└──╼ {Fore.WHITE}Enter target URL {Fore.CYAN}(e.g., https://example.com){Style.RESET_ALL}")
                
                url = input(f"\n{Fore.GREEN}➜ {Style.RESET_ALL}").strip()
                
                if not url:
                    print(f"{Fore.RED}✗ URL cannot be empty{Style.RESET_ALL}")
                    continue
                
                # Add https:// if no scheme provided
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                # Validate URL format
                parsed = urlparse(url)
                if not parsed.netloc:
                    print(f"{Fore.RED}✗ Invalid URL format{Style.RESET_ALL}")
                    continue
                
                return url
            except KeyboardInterrupt:
                self.signal_handler(None, None)
                return None
            except Exception as e:
                print(f"{Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")
    
    def check_connectivity(self, url):
        """Perform connectivity pre-check with enhanced UI"""
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}              CONNECTIVITY PRE-FLIGHT CHECK{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
        
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        checks = []
        
        # DNS Resolution Check
        print(f"{Fore.CYAN}[1/4]{Style.RESET_ALL} Resolving DNS for {Fore.WHITE}{hostname}{Style.RESET_ALL}...", end=' ', flush=True)
        time.sleep(0.5)  # Visible pause
        try:
            ip_address = socket.gethostbyname(hostname)
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} [{Fore.YELLOW}{ip_address}{Style.RESET_ALL}]")
            checks.append(True)
        except socket.gaierror:
            print(f"{Fore.RED}✗ DNS resolution failed{Style.RESET_ALL}")
            checks.append(False)
            return False
        
        time.sleep(0.3)
        
        # Port Connectivity Check
        print(f"{Fore.CYAN}[2/4]{Style.RESET_ALL} Checking port {Fore.WHITE}{port}{Style.RESET_ALL} connectivity...", end=' ', flush=True)
        time.sleep(0.5)  # Visible pause
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                print(f"{Fore.GREEN}✓ Port is open{Style.RESET_ALL}")
                checks.append(True)
            else:
                print(f"{Fore.RED}✗ Port is closed or filtered{Style.RESET_ALL}")
                checks.append(False)
                return False
        except Exception as e:
            print(f"{Fore.RED}✗ Connection failed{Style.RESET_ALL}")
            checks.append(False)
            return False
        
        time.sleep(0.3)
        
        # HTTP/HTTPS Availability Check
        print(f"{Fore.CYAN}[3/4]{Style.RESET_ALL} Testing {Fore.WHITE}{parsed.scheme.upper()}{Style.RESET_ALL} connectivity...", end=' ', flush=True)
        time.sleep(0.5)  # Visible pause
        try:
            response = requests.get(url, timeout=10, allow_redirects=False, verify=False)
            print(f"{Fore.GREEN}✓ Response received{Style.RESET_ALL} [{Fore.YELLOW}{response.status_code}{Style.RESET_ALL}]")
            checks.append(True)
        except requests.exceptions.SSLError:
            print(f"{Fore.YELLOW}⚠ SSL/TLS error (certificate issue){Style.RESET_ALL}")
            checks.append(True)
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}✗ Request timeout{Style.RESET_ALL}")
            checks.append(False)
            return False
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}✗ Connection refused{Style.RESET_ALL}")
            checks.append(False)
            return False
        except Exception as e:
            print(f"{Fore.RED}✗ Error: {str(e)[:50]}{Style.RESET_ALL}")
            checks.append(False)
            return False
        
        time.sleep(0.3)
        
        # Latency Check
        print(f"{Fore.CYAN}[4/4]{Style.RESET_ALL} Measuring latency...", end=' ', flush=True)
        time.sleep(0.5)  # Visible pause
        try:
            start = time.time()
            requests.get(url, timeout=5, verify=False)
            latency = (time.time() - start) * 1000
            
            if latency < 100:
                color = Fore.GREEN
            elif latency < 500:
                color = Fore.YELLOW
            else:
                color = Fore.RED
            
            print(f"{color}✓ {latency:.0f}ms{Style.RESET_ALL}")
            checks.append(True)
        except:
            print(f"{Fore.YELLOW}⚠ Unable to measure{Style.RESET_ALL}")
            checks.append(True)
        
        time.sleep(0.5)
        
        # Summary
        success_rate = (sum(checks) / len(checks)) * 100
        print(f"\n{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
        print(f" Status: {Fore.GREEN}✓ Target is reachable{Style.RESET_ALL}")
        print(f" Success Rate: {Fore.YELLOW}{success_rate:.0f}%{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}\n")
        
        return True
    
    def display_banner(self):
        """Display enhanced ASCII art banner with animations"""
        if not self.banner_shown:
            # Animated stars effect
            print()
            AnimatedBanner.animated_stars()
            time.sleep(0.3)
        
        # Main banner with gradient effect
        banner_lines = [
            "    ____           ____                    ",
            "   / __ \\___  ____/ / /   ___  ____  _____ ",
            "  / /_/ / _ \\/ __  / /   / _ \\/ __ \\/ ___/ ",
            " / _, _/  __/ /_/ / /___/  __/ / / (__  )  ",
            "/_/ |_|\\___/\\__,_/_____/\\___/_/ /_/____/   "
        ]
        
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
        
        for line in banner_lines:
            colored_line = AnimatedBanner.gradient_text(line, colors)
            print(colored_line)
            time.sleep(0.1)  # Slower reveal
        
        time.sleep(0.3)
        
        # Animated separator
        print()
        for i in range(71):
            print(f"\r{Fore.CYAN}{'═' * i}{Style.RESET_ALL}", end='', flush=True)
            time.sleep(0.01)
        print()
        
        # Info section
        print(f"{Fore.YELLOW}     ⚡ Professional Web Application Security Scanner ⚡{Style.RESET_ALL}")
        print(f"              {Fore.GREEN}Created by Monish Kanna{Style.RESET_ALL}")
        print(f"      {Fore.BLUE}GitHub: https://github.com/TENETx0/Redlens{Style.RESET_ALL}")
        print(f"                   {Fore.MAGENTA}Version {self.version}{Style.RESET_ALL}")
        
        # Animated separator
        for i in range(71):
            print(f"\r{Fore.CYAN}{'═' * i}{Style.RESET_ALL}", end='', flush=True)
            time.sleep(0.01)
        print()
        
        # Stats bar if target is set
        if self.target_url:
            print(f"\n{Fore.YELLOW}┌─[{Fore.WHITE}Current Target{Fore.YELLOW}]")
            print(f"└──╼ {Fore.CYAN}{self.target_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}┌─[{Fore.WHITE}Scans Completed{Fore.YELLOW}]")
            print(f"└──╼ {Fore.GREEN}{self.scan_count}{Style.RESET_ALL}")
        
        self.banner_shown = True
    
    def display_menu(self):
        """Display professional menu without boxes and emojis"""
        print(f"\n{Fore.MAGENTA}{'─' * 70}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}                    SCANNING MODULES{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'─' * 70}{Style.RESET_ALL}\n")
        
        menu_options = [
            ("1", "Pre-flight Validation", Fore.GREEN),
            ("2", "Passive Reconnaissance", Fore.CYAN),
            ("3", "TLS / SSL Analysis", Fore.YELLOW),
            ("4", "HTTP Security Header Analysis", Fore.BLUE),
            ("5", "Technology Fingerprinting", Fore.MAGENTA),
            ("6", "Application Surface Mapping", Fore.GREEN),
            ("7", "Directory & File Discovery", Fore.CYAN),
            ("8", "Authentication & Session Analysis", Fore.YELLOW),
            ("9", "Input Validation & Weak Signal Detection", Fore.RED),
            ("10", "API Reconnaissance", Fore.BLUE),
            ("11", "Cloud & Hosting Exposure Analysis", Fore.MAGENTA),
        ]
        
        for num, option, color in menu_options:
            padding = " " * (2 - len(num))
            print(f"  {color}[{num}]{padding}  {Fore.WHITE}{option}{Style.RESET_ALL}")
        
        # Advanced options - single line, no box
        print(f"\n  {Fore.BLUE}[12]{Style.RESET_ALL}  {Fore.WHITE}Select Multiple Scans{Style.RESET_ALL}     {Fore.YELLOW}[13]{Style.RESET_ALL}  {Fore.WHITE}Change Target{Style.RESET_ALL}     {Fore.GREEN}[14]{Style.RESET_ALL}  {Fore.WHITE}Run All Modules{Style.RESET_ALL}")
        
        # Exit option
        print(f"\n  {Fore.RED}[0]   Exit Redlense{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}\n")
    
    def get_user_choice(self):
        """Get and validate user input with enhanced prompt"""
        try:
            choice = input(f"{Fore.YELLOW}┌─[{Fore.WHITE}redlense{Fore.YELLOW}]─[{Fore.CYAN}main-menu{Fore.YELLOW}]\n└──╼ {Fore.GREEN}$ {Style.RESET_ALL}").strip()
            return choice
        except EOFError:
            self.exit_program()
        except KeyboardInterrupt:
            self.signal_handler(None, None)
            return None
    
    def execute_module(self, choice):
        """Execute the selected module with enhanced feedback"""
        modules = {
            '1': ('Pre-flight Validation', 'modules.preflight'),
            '2': ('Passive Reconnaissance', 'modules.passive'),
            '3': ('TLS / SSL Analysis', 'modules.tls'),
            '4': ('HTTP Security Header Analysis', 'modules.headers'),
            '5': ('Technology Fingerprinting', 'modules.tech'),
            '6': ('Application Surface Mapping', 'modules.crawler'),
            '7': ('Directory & File Discovery', 'modules.discovery'),
            '8': ('Authentication & Session Analysis', 'modules.auth'),
            '9': ('Input Validation & Weak Signal Detection', 'modules.validation'),
            '10': ('API Reconnaissance', 'modules.api'),
            '11': ('Cloud & Hosting Exposure Analysis', 'modules.cloud'),
        }
        
        if choice == '0':
            self.exit_program()
        
        elif choice == '12':
            self.run_multiple_scans(modules)
        
        elif choice == '13':
            self.change_target()
        
        elif choice == '14':
            self.run_all_modules(modules)
        
        elif choice in modules:
            module_name, module_path = modules[choice]
            
            print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}  🚀 Launching: {module_name}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[i] Press Ctrl+C to suspend scan{Style.RESET_ALL}\n")
            
            # Animated loading
            self.animated_loading("Initializing module", 1.0)
            
            try:
                from importlib import import_module
                module = import_module(module_path)
                
                if hasattr(module, 'run'):
                    start_time = time.time()
                    module.run(self.target_url)
                    elapsed = time.time() - start_time
                    
                    self.scan_count += 1
                    
                    # Success message
                    print(f"\n{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}  ✓ Scan completed in {elapsed:.2f}s{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Module {module_name} does not have a run function{Style.RESET_ALL}")
            except ModuleNotFoundError:
                print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
                print(f"{Fore.RED}  ✗ Module Not Found: {module_name}{Style.RESET_ALL}")
                print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Please ensure the module file exists at: {module_path.replace('.', '/')}.py{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error executing module: {str(e)}{Style.RESET_ALL}")
            
            input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
            
        elif choice.lower() == 'menu':
            return
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please try again.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
    
    def run_multiple_scans(self, modules):
        """Run multiple selected scans"""
        print(f"\n{Fore.BLUE}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}              SELECT MULTIPLE SCANS{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'═' * 70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}Available Modules:{Style.RESET_ALL}\n")
        for num, (module_name, _) in modules.items():
            print(f"  {Fore.GREEN}[{num}]{Style.RESET_ALL} {module_name}")
        
        print(f"\n{Fore.YELLOW}┌─[{Fore.WHITE}Selection Guide{Fore.YELLOW}]")
        print(f"├──╼ Enter module numbers separated by commas (e.g., 1,4,7,10)")
        print(f"└──╼ Or enter 'all' to run all modules{Style.RESET_ALL}\n")
        
        try:
            selection = input(f"{Fore.GREEN}➜ {Style.RESET_ALL}").strip()
            
            if selection.lower() == 'all':
                selected = list(modules.keys())
            else:
                selected = [s.strip() for s in selection.split(',')]
                selected = [s for s in selected if s in modules]
            
            if not selected:
                print(f"{Fore.RED}[!] No valid modules selected{Style.RESET_ALL}")
                input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
                return
            
            print(f"\n{Fore.GREEN}[+] Running {len(selected)} module(s)...{Style.RESET_ALL}\n")
            time.sleep(0.5)
            
            for i, module_num in enumerate(selected, 1):
                module_name, module_path = modules[module_num]
                
                print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}  [{i}/{len(selected)}] {module_name}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
                
                try:
                    from importlib import import_module
                    module = import_module(module_path)
                    
                    if hasattr(module, 'run'):
                        module.run(self.target_url)
                        self.scan_count += 1
                    else:
                        print(f"{Fore.RED}[!] Module missing run function{Style.RESET_ALL}")
                
                except ModuleNotFoundError:
                    print(f"{Fore.RED}[!] Module not found: {module_path}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
                
                if i < len(selected):
                    print(f"\n{Fore.YELLOW}[*] Moving to next module in 2 seconds...{Style.RESET_ALL}")
                    time.sleep(2)
            
            print(f"\n{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}  ✓ All selected scans completed!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}\n")
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Multiple scan interrupted{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        
        input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
    
    def change_target(self):
        """Change target URL"""
        print(f"\n{Fore.BLUE}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}                CHANGE TARGET URL{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'═' * 70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}┌─[{Fore.WHITE}Current Target{Fore.YELLOW}]")
        print(f"└──╼ {Fore.CYAN}{self.target_url}{Style.RESET_ALL}\n")
        
        new_url = self.get_target_url()
        
        if new_url:
            if self.check_connectivity(new_url):
                self.target_url = new_url
                print(f"\n{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}  ✓ Target updated successfully!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}┌─[{Fore.WHITE}New Target{Fore.YELLOW}]")
                print(f"└──╼ {Fore.CYAN}{self.target_url}{Style.RESET_ALL}\n")
            else:
                print(f"\n{Fore.RED}[!] New target is unreachable{Style.RESET_ALL}")
                retry = input(f"{Fore.YELLOW}[?] Use it anyway? (y/N): {Style.RESET_ALL}").strip().lower()
                if retry == 'y':
                    self.target_url = new_url
                    print(f"{Fore.YELLOW}[!] Target updated (connectivity not verified){Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] Keeping current target{Style.RESET_ALL}")
        
        input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
    
    def run_all_modules(self, modules):
        """Run all modules in sequence"""
        print(f"\n{Fore.BLUE}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}            COMPLETE SCAN - ALL MODULES{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'═' * 70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}┌─[{Fore.WHITE}Configuration{Fore.YELLOW}]")
        print(f"├──╼ Target: {Fore.CYAN}{self.target_url}{Style.RESET_ALL}")
        print(f"├──╼ Modules: {Fore.GREEN}{len(modules)}{Style.RESET_ALL}")
        print(f"└──╼ Estimated Time: {Fore.YELLOW}10-30 minutes{Style.RESET_ALL}\n")
        
        confirm = input(f"{Fore.CYAN}[?] Continue with complete scan? (y/N): {Style.RESET_ALL}").strip().lower()
        
        if confirm != 'y':
            print(f"{Fore.YELLOW}[!] Complete scan cancelled{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] Starting complete scan...{Style.RESET_ALL}\n")
        time.sleep(0.5)
        
        start_time = time.time()
        successful = 0
        failed = 0
        
        for i, (module_num, (module_name, module_path)) in enumerate(modules.items(), 1):
            # Progress bar
            progress = (i / len(modules)) * 100
            filled = int(progress / 2)
            bar = '█' * filled + '░' * (50 - filled)
            
            print(f"\n{Fore.CYAN}[{bar}] {progress:.0f}%{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  [{i}/{len(modules)}] {module_name}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
            
            try:
                from importlib import import_module
                module = import_module(module_path)
                
                if hasattr(module, 'run'):
                    module.run(self.target_url)
                    successful += 1
                    self.scan_count += 1
                else:
                    print(f"{Fore.RED}[!] Module missing run function{Style.RESET_ALL}")
                    failed += 1
            
            except ModuleNotFoundError:
                print(f"{Fore.RED}[!] Module not found: {module_path}{Style.RESET_ALL}")
                failed += 1
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
                failed += 1
            
            if i < len(modules):
                print(f"\n{Fore.YELLOW}[*] Moving to next module...{Style.RESET_ALL}")
                time.sleep(1)
        
        elapsed = time.time() - start_time
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        
        # Final summary
        print(f"\n{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}              COMPLETE SCAN FINISHED{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}┌─[{Fore.WHITE}Statistics{Fore.CYAN}]")
        print(f"├──╼ Successful: {Fore.GREEN}{successful}{Style.RESET_ALL}")
        print(f"├──╼ Failed: {Fore.RED}{failed}{Style.RESET_ALL}")
        print(f"├──╼ Duration: {Fore.YELLOW}{minutes}m {seconds}s{Style.RESET_ALL}")
        print(f"└──╼ Reports: {Fore.CYAN}./Results/{Style.RESET_ALL}\n")
        
        input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
    
    def exit_program(self):
        """Exit the program gracefully with style"""
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}                  EXITING REDLENS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
        
        if self.scan_count > 0:
            print(f"{Fore.GREEN}[✓] Total scans completed: {self.scan_count}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[✓] Results saved in: ./Results/{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[*] Stay secure! Happy hunting!{Style.RESET_ALL}\n")
        sys.exit(0)
    
    def run(self):
        """Main program loop"""
        self.clear_screen()
        self.display_banner()
        
        # Get target URL and perform connectivity check
        self.target_url = self.get_target_url()
        if not self.target_url:
            return
        
        if not self.check_connectivity(self.target_url):
            print(f"\n{Fore.RED}[!] Target is unreachable. Please check the URL and try again.{Style.RESET_ALL}")
            retry = input(f"{Fore.YELLOW}[?] Do you want to continue anyway? (y/N): {Style.RESET_ALL}").strip().lower()
            if retry != 'y':
                self.exit_program()
        
        while self.running:
            self.display_menu()
            choice = self.get_user_choice()
            
            if choice is not None:
                if choice.lower() == 'exit':
                    self.exit_program()
                else:
                    self.execute_module(choice)
                    self.clear_screen()
                    self.display_banner()


def main():
    """Entry point of the application"""
    try:
        menu = RedlenseMenu()
        menu.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Program interrupted. Exiting...{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
