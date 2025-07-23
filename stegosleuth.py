#!/usr/bin/env python3
"""
StegoSleuth - Automated Steganography Detection Tool
A comprehensive tool for detecting and extracting hidden data from images in CTF challenges.
"""

import os
import sys
import click
import magic
import cv2
import numpy as np
from PIL import Image, ExifTags
import exifread
import subprocess
import binascii
from colorama import init, Fore, Back, Style
import tempfile
import shutil
from datetime import datetime

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class StegoSleuth:
    def __init__(self, image_path, verbose=False):
        self.image_path = image_path
        self.verbose = verbose
        self.results = []
        
    def log(self, message, level="INFO"):
        """Log messages with color coding"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "FOUND": Fore.MAGENTA
        }
        
        if self.verbose or level in ["SUCCESS", "FOUND", "ERROR"]:
            print(f"{colors.get(level, '')}{level}: {message}{Style.RESET_ALL}")
    
    def add_result(self, check_type, status, details=""):
        """Add result to results list"""
        result = {
            "check": check_type,
            "status": status,
            "details": details
        }
        self.results.append(result)
        
        if status == "FOUND":
            self.log(f"{check_type}: {details}", "FOUND")
        elif self.verbose:
            self.log(f"{check_type}: {status}", "INFO")
    
    def check_file_signature(self):
        """Check if file signature matches the extension"""
        self.log("Checking file signature vs extension...", "INFO")
        
        try:
            # Get file extension
            _, ext = os.path.splitext(self.image_path)
            ext = ext.lower()
            
            # Get actual file type using python-magic
            file_type = magic.from_file(self.image_path).lower()
            
            # Common mismatches to look for
            mismatches = []
            
            if ext == '.png' and 'jpeg' in file_type:
                mismatches.append(f"File has .png extension but is actually JPEG")
            elif ext == '.jpg' and 'png' in file_type:
                mismatches.append(f"File has .jpg extension but is actually PNG")
            elif ext == '.bmp' and ('jpeg' in file_type or 'png' in file_type):
                mismatches.append(f"File has .bmp extension but is actually {file_type}")
            
            if mismatches:
                self.add_result("File Signature Check", "FOUND", "; ".join(mismatches))
            else:
                self.add_result("File Signature Check", "OK", f"Extension matches file type: {file_type}")
                
        except Exception as e:
            self.add_result("File Signature Check", "ERROR", str(e))
    
    def extract_metadata(self):
        """Extract and analyze image metadata"""
        self.log("Extracting image metadata...", "INFO")
        
        try:
            with open(self.image_path, 'rb') as f:
                tags = exifread.process_file(f)
                
            if tags:
                suspicious_tags = []
                for tag in tags.keys():
                    if tag not in ['JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote']:
                        tag_value = str(tags[tag])
                        # Look for suspicious or unusual metadata
                        if any(keyword in tag_value.lower() for keyword in ['flag', 'ctf', 'hidden', 'secret', 'password']):
                            suspicious_tags.append(f"{tag}: {tag_value}")
                
                if suspicious_tags:
                    self.add_result("Metadata Analysis", "FOUND", "; ".join(suspicious_tags))
                else:
                    self.add_result("Metadata Analysis", "OK", f"Found {len(tags)} metadata tags, none suspicious")
            else:
                self.add_result("Metadata Analysis", "OK", "No EXIF metadata found")
                
        except Exception as e:
            self.add_result("Metadata Analysis", "ERROR", str(e))
    
    def check_lsb_steganography(self):
        """Check for LSB (Least Significant Bit) steganography"""
        self.log("Checking for LSB steganography...", "INFO")
        
        try:
            img = cv2.imread(self.image_path)
            if img is None:
                self.add_result("LSB Check", "ERROR", "Could not load image")
                return
            
            # Extract LSB from each channel
            lsb_data = []
            for channel in range(3):  # BGR channels
                channel_data = img[:, :, channel]
                lsb_bits = channel_data & 1  # Get LSB
                lsb_data.extend(lsb_bits.flatten())
            
            # Convert bits to bytes and look for readable text
            byte_data = []
            for i in range(0, len(lsb_data) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val += lsb_data[i + j] * (2 ** j)
                byte_data.append(byte_val)
            
            # Look for readable ASCII text in the first 1000 bytes
            text_data = ''.join([chr(b) for b in byte_data[:1000] if 32 <= b <= 126])
            
            if len(text_data) > 20 and any(word in text_data.lower() for word in ['flag', 'ctf', 'the', 'and', 'is']):
                self.add_result("LSB Steganography", "FOUND", f"Possible hidden text: {text_data[:100]}...")
            else:
                self.add_result("LSB Steganography", "OK", "No obvious LSB steganography detected")
                
        except Exception as e:
            self.add_result("LSB Steganography", "ERROR", str(e))
    
    def check_hidden_files(self):
        """Use binwalk to check for hidden files"""
        self.log("Checking for hidden files with binwalk...", "INFO")
        
        try:
            # Run binwalk
            result = subprocess.run(['binwalk', self.image_path], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output = result.stdout
                lines = output.split('\n')
                
                # Look for embedded files
                embedded_files = []
                for line in lines:
                    if any(filetype in line.lower() for filetype in 
                          ['zip', 'rar', 'tar', 'gzip', 'pdf', 'exe', 'elf', 'jpeg', 'png']):
                        embedded_files.append(line.strip())
                
                if embedded_files:
                    self.add_result("Hidden Files Check", "FOUND", 
                                  f"Found {len(embedded_files)} embedded files: " + "; ".join(embedded_files[:3]))
                else:
                    self.add_result("Hidden Files Check", "OK", "No embedded files detected")
            else:
                self.add_result("Hidden Files Check", "ERROR", f"binwalk error: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.add_result("Hidden Files Check", "ERROR", "binwalk timeout")
        except FileNotFoundError:
            self.add_result("Hidden Files Check", "ERROR", "binwalk not installed")
        except Exception as e:
            self.add_result("Hidden Files Check", "ERROR", str(e))
    
    def check_strings(self):
        """Extract and analyze strings from the image file"""
        self.log("Extracting strings from image...", "INFO")
        
        try:
            with open(self.image_path, 'rb') as f:
                data = f.read()
            
            # Extract printable strings (at least 4 characters long)
            strings = []
            current_string = ""
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
            
            # Add the last string if it's long enough
            if len(current_string) >= 4:
                strings.append(current_string)
            
            # Look for suspicious strings
            suspicious_strings = []
            keywords = ['flag', 'ctf', 'password', 'secret', 'hidden', 'key', 'base64', 'cipher']
            
            for string in strings:
                if any(keyword in string.lower() for keyword in keywords):
                    suspicious_strings.append(string)
            
            if suspicious_strings:
                self.add_result("String Analysis", "FOUND", 
                              f"Found {len(suspicious_strings)} suspicious strings: " + 
                              "; ".join(suspicious_strings[:3]))
            else:
                self.add_result("String Analysis", "OK", f"Extracted {len(strings)} strings, none suspicious")
                
        except Exception as e:
            self.add_result("String Analysis", "ERROR", str(e))
    
    def check_color_analysis(self):
        """Analyze color channels for anomalies"""
        self.log("Analyzing color channels...", "INFO")
        
        try:
            img = cv2.imread(self.image_path)
            if img is None:
                self.add_result("Color Analysis", "ERROR", "Could not load image")
                return
            
            # Split channels
            b, g, r = cv2.split(img)
            
            # Calculate statistics for each channel
            channels = {'Blue': b, 'Green': g, 'Red': r}
            anomalies = []
            
            for name, channel in channels.items():
                mean_val = np.mean(channel)
                std_val = np.std(channel)
                
                # Check for unusual patterns (very low std deviation might indicate hidden data)
                if std_val < 10 and mean_val > 50:
                    anomalies.append(f"{name} channel has unusually low variation (std: {std_val:.2f})")
            
            if anomalies:
                self.add_result("Color Analysis", "FOUND", "; ".join(anomalies))
            else:
                self.add_result("Color Analysis", "OK", "No color channel anomalies detected")
                
        except Exception as e:
            self.add_result("Color Analysis", "ERROR", str(e))
    
    def run_all_checks(self):
        """Run all steganography detection checks"""
        self.log(f"Starting analysis of {self.image_path}", "INFO")
        
        # Run all detection methods
        self.check_file_signature()
        self.extract_metadata()
        self.check_lsb_steganography()
        self.check_hidden_files()
        self.check_strings()
        self.check_color_analysis()
        
        return self.results
    
    def run_specific_check(self, check_type):
        """Run a specific check"""
        checks = {
            'signature': self.check_file_signature,
            'metadata': self.extract_metadata,
            'lsb': self.check_lsb_steganography,
            'hidden': self.check_hidden_files,
            'strings': self.check_strings,
            'colors': self.check_color_analysis
        }
        
        if check_type in checks:
            checks[check_type]()
            return self.results
        else:
            self.log(f"Unknown check type: {check_type}", "ERROR")
            return []

@click.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.option('--check', '-c', 
              type=click.Choice(['signature', 'metadata', 'lsb', 'hidden', 'strings', 'colors']),
              help='Run a specific check instead of all checks')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def main(image_path, check, verbose, output):
    """
    StegoSleuth - Automated Steganography Detection Tool
    
    Analyze images for hidden data commonly found in CTF challenges.
    """
    
    # Display banner
    banner = f"""
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                        StegoSleuth v1.0                      ║
║              Automated Steganography Detection               ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)
    
    # Initialize the tool
    sleuth = StegoSleuth(image_path, verbose)
    
    # Run checks
    if check:
        print(f"Running specific check: {check}")
        results = sleuth.run_specific_check(check)
    else:
        print("Running all checks...")
        results = sleuth.run_all_checks()
    
    # Display summary
    print(f"\n{Fore.YELLOW}═══ ANALYSIS SUMMARY ═══{Style.RESET_ALL}")
    
    found_count = sum(1 for r in results if r['status'] == 'FOUND')
    ok_count = sum(1 for r in results if r['status'] == 'OK')
    error_count = sum(1 for r in results if r['status'] == 'ERROR')
    
    print(f"Total checks: {len(results)}")
    print(f"{Fore.GREEN}Passed: {ok_count}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Findings: {found_count}{Style.RESET_ALL}")
    print(f"{Fore.RED}Errors: {error_count}{Style.RESET_ALL}")
    
    if found_count > 0:
        print(f"\n{Fore.MAGENTA}🎯 POTENTIAL STEGANOGRAPHY DETECTED!{Style.RESET_ALL}")
        print("Review the findings above for hidden data.")
    else:
        print(f"\n{Fore.GREEN}✓ No obvious steganography detected.{Style.RESET_ALL}")
    
    # Save results if requested
    if output:
        with open(output, 'w') as f:
            f.write(f"StegoSleuth Analysis Results\n")
            f.write(f"Image: {image_path}\n")
            f.write(f"Timestamp: {datetime.now()}\n\n")
            
            for result in results:
                f.write(f"Check: {result['check']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Details: {result['details']}\n\n")
        
        print(f"\n📁 Results saved to: {output}")

if __name__ == '__main__':
    main()
