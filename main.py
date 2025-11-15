# Simple Process Memory Scanner (SPMS) 
# Copyright: 2025 Luna River 

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import re
import os
import sys
import subprocess

def check_root_privileges():
    if os.geteuid() != 0:
        print("error: you cannot use this program unless you are root.")
        sys.exit(1)

def find_existing_process_files():
    process_files = []
    for filename in os.listdir("/tmp"):
        if filename.startswith(".process.") and filename.endswith(".txt"):
            pid = filename.split(".")[2]
            process_files.append((pid, os.path.join("/tmp", filename)))
    return process_files

def ask_use_existing_process(process_files):
    if not process_files:
        return None
    
    print("\nFound existing process files:")
    for i, (pid, filepath) in enumerate(process_files, 1):
        print(f"{i}) PID: {pid} - {filepath}")
    
    print(f"{len(process_files) + 1}) Scan new process")
    
    while True:
        try:
            choice = input("\nSelect option: ").strip()
            if not choice:
                continue
                
            choice_num = int(choice)
            if 1 <= choice_num <= len(process_files):
                return process_files[choice_num - 1][0]
            elif choice_num == len(process_files) + 1:
                return None
            else:
                print("Invalid selection")
        except ValueError:
            print("Please enter a valid number")

def extract_minecraft_version(cmd_line):
    patterns = [
        r'minecraft[\/\\](\d+\.\d+(?:\.\d+)?)',  # minecraft/1.21.4
        r'versions[\/\\](\d+\.\d+(?:\.\d+)?)',   # versions/1.21.4
        r'--version\s+(\d+\.\d+(?:\.\d+)?)',     # --version 1.21.4
        r'/(\d+\.\d+(?:\.\d+)?)/minecraft',      # /1.21.4/minecraft
        r'(\d+\.\d+(?:\.\d+)?)-OptiFine',        # 1.16.5-OptiFine
        r'fabric[\/\\](\d+\.\d+(?:\.\d+)?)',     # fabric/1.21.4
        r'instances[\/\\][^\/\\]+[\/\\](\d+\.\d+(?:\.\d+)?)'  # instances/1.21.4 fabric
    ]
    
    for pattern in patterns:
        match = re.search(pattern, cmd_line, re.IGNORECASE)
        if match:
            return match.group(1)
    
    jar_pattern = r'/(\d+\.\d+(?:\.\d+)?)[^/]*\.jar'
    match = re.search(jar_pattern, cmd_line)
    if match:
        return match.group(1)
    
    return "Unknown version"

def extract_launcher_info(cmd_line):
    if 'PrismLauncher' in cmd_line:
        return "PrismLauncher"
    elif 'minecraft-launcher' in cmd_line or '/.minecraft/' in cmd_line:
        return "Official Launcher"
    elif 'fabric' in cmd_line.lower():
        return "Fabric"
    elif 'optifine' in cmd_line.lower():
        return "OptiFine"
    else:
        return "Unknown launcher"

def find_java_processes():
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        java_processes = []
        
        for line in result.stdout.split('\n'):
            if 'java' in line and any(keyword in line.lower() for keyword in ['minecraft', 'prismlauncher', 'fabric', 'optifine']):
                parts = line.split()
                if len(parts) >= 2:
                    pid = parts[1]
                    cmd = ' '.join(parts[10:])
                    
                    version = extract_minecraft_version(cmd)
                    launcher = extract_launcher_info(cmd)
                    
                    java_processes.append((pid, cmd, version, launcher))
        
        return java_processes
    except Exception as e:
        print(f"Error finding Java processes: {e}")
        return []

def select_java_process(java_processes):
    if not java_processes:
        print("No Minecraft Java processes found (maybe user did not start minecraft?)")
        return None
    
    print("\nFound Minecraft Java processes:")
    for i, (pid, cmd, version, launcher) in enumerate(java_processes, 1):
        short_cmd = cmd[:80] + "..." if len(cmd) > 80 else cmd
        print(f"{i}) PID: {pid}")
        print(f"   Version: {version} | Launcher: {launcher}")
        print(f"   Command: {short_cmd}")
    
    while True:
        try:
            choice = input("Select process: ").strip()
            if not choice:
                continue
                
            choice_num = int(choice)
            if 1 <= choice_num <= len(java_processes):
                return java_processes[choice_num - 1][0]
            else:
                print("Invalid selection")
        except ValueError:
            print("Please enter a valid number")

def get_pid_manually():
    while True:
        try:
            pid = input("Enter PID: ").strip()
            if pid and pid.isdigit():
                return pid
            else:
                print("Please enter a valid PID number")
        except KeyboardInterrupt:
            return None

def select_pid_method():
    print("\nSelect PID method:")
    print("1) Try to find Minecraft PID automatically")
    print("2) Select PID manually")
    print("3) Exit program")
    
    while True:
        choice = input("\nSelect option: ").strip()
        if choice == '1':
            java_processes = find_java_processes()
            pid = select_java_process(java_processes)
            if pid:
                return pid
            else:
                print("No suitable process found, try manual selection")
        elif choice == '2':
            return get_pid_manually()
        elif choice == '3':
            print("Exiting program...")
            sys.exit(0)
        else:
            print("Invalid selection, please choose 1, 2 or 3")

def dump_process_memory(pid):
    output_file = f"/tmp/.process.{pid}.txt"
    
    try:
        with open(f"/proc/{pid}/maps") as maps, \
             open(f"/proc/{pid}/mem", "rb") as mem, \
             open(output_file, "w", encoding='utf-8', errors='ignore') as out:
            
            for line in maps:
                addr_range, perms, *_ = line.split(maxsplit=5)
                if 'r' not in perms:
                    continue
                
                start_s, end_s = addr_range.split('-')
                start = int(start_s, 16)
                end = int(end_s, 16)
                size = end - start
                
                mem.seek(start)
                try:
                    chunk = mem.read(size)
                except Exception:
                    continue
                
                for m in re.finditer(b'[\\x20-\\x7E]{4,}', chunk):
                    try:
                        s = m.group().decode('ascii')
                        out.write(s + "\n")
                    except:
                        pass
        
        print(f"Memory dumped to: {output_file}")
        return output_file
    except Exception as e:
        print(f"Error dumping memory for PID {pid}: {e}")
        return None

def search_strings_in_dump(pid):
    dump_file = f"/tmp/.process.{pid}.txt"
    
    if not os.path.exists(dump_file):
        print(f"Dump file not found: {dump_file}")
        return
    
    search_string = input("Please enter your string: ").strip()
    if not search_string:
        print("No search string provided")
        return
    
    try:
        result = subprocess.run(
            ['grep', search_string, dump_file],
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            print("\nFound strings:")
            print(result.stdout)
        else:
            print("No matches found")
            
    except Exception as e:
        print(f"Error searching strings: {e}")

def main_menu(pid):
    while True:
        print(f"\nCurrent PID: {pid}")
        print("1) Check for string")
        print("2) Scan other PID")
        print("3) Exit program")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            search_strings_in_dump(pid)
            input("\nPress enter to continue...")
        elif choice == '2':
            return True
        elif choice == '3':
            print("Exiting program...")
            sys.exit(0)
        else:
            print("Invalid selection")

def main():
    check_root_privileges()
    
    print("Simple Process Memory Scanner (SPMS)")
    print("\nBy Snowy-Fluffy (snowyfl.com)")
    print("\nDistributed as open source program under GPL v3.0 on https://github.com/Snowy-Fluffy/SPMS")
    print("=" * 40)
    
    while True:
        process_files = find_existing_process_files()
        
        if process_files:
            use_existing = input("\nFound existing process dump files. Use existing? (y/n): ").strip().lower()
            if use_existing == 'y':
                selected_pid = ask_use_existing_process(process_files)
                if selected_pid:
                    if main_menu(selected_pid):
                        continue
                    else:
                        break
                else:
                    pass
            elif use_existing == 'n':
                pass
            else:
                print("Invalid input, proceeding to PID selection")
        
        pid = select_pid_method()
        if not pid:
            continue
        print(f"\nDumping memory for PID {pid}...")
        dump_file = dump_process_memory(pid)
        
        if dump_file:
            if main_menu(pid):
                continue
            else:
                break

if __name__ == "__main__":
    main()
