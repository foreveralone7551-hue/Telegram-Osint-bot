import subprocess
import os
import sys
import json
from pathlib import Path
from datetime import datetime
import asyncio
from asyncio.subprocess import PIPE


BLACKBIRD_DIR = Path(__file__).resolve().parents[1] / "blackbird-osint"
BLACKBIRD_SCRIPT = str(BLACKBIRD_DIR / "blackbird.py")
BLACKBIRD_WRAPPER = str(Path(__file__).resolve().parents[1] / "run_blackbird.py")
BLACKBIRD_TIMEOUT = 180
BLACKBIRD_MAX_CONCURRENT = 10


def read_json_output(identifier: str) -> str:
	"""Read JSON results for the exact identifier string (may include spaces)."""
	date_raw = datetime.now().strftime("%m_%d_%Y")
	
	# Try different variations of the identifier
	variations = [identifier]
	if " " in identifier:
		variations += [
			identifier.replace(" ", ""),
			identifier.replace(" ", "_"),
			identifier.replace(" ", "-"),
			identifier.replace(" ", "."),
		]
	
	# Also try with different cases
	all_variations = []
	for var in variations:
		all_variations.extend([var, var.lower(), var.upper()])
	
	# Remove duplicates while preserving order
	seen = set()
	unique_variations = []
	for var in all_variations:
		if var not in seen:
			seen.add(var)
			unique_variations.append(var)
	
	# First try: Look for files directly in results directory (current format)
	results_dir = BLACKBIRD_DIR / "results"
	if results_dir.exists():
		for ident in unique_variations:
			# Try the current format: identifier_date_blackbird.json
			json_file = results_dir / f"{ident}_{date_raw}_blackbird.json"
			try:
				if json_file.exists():
					return json_file.read_text(encoding="utf-8")
			except Exception:
				pass
		
		# Second try: Look for any JSON file that contains the identifier
		for json_file in results_dir.glob("*.json"):
			try:
				if json_file.is_file():
					# Check if the identifier is similar to the filename
					filename = json_file.stem  # filename without extension
					if (identifier.lower() in filename.lower() or 
						filename.lower() in identifier.lower() or
						any(var.lower() in filename.lower() for var in variations)):
						return json_file.read_text(encoding="utf-8")
			except Exception:
				pass
	
	# Third try: Look in subdirectories (old format)
	for ident in unique_variations:
		base = BLACKBIRD_DIR / "results" / f"{ident}_{date_raw}_blackbird" / f"{ident}_{date_raw}_blackbird.json"
		try:
			if base.exists():
				return base.read_text(encoding="utf-8")
		except Exception:
			pass
	
	# If no exact match found, try to find any file with similar name in subdirectories
	try:
		if results_dir.exists():
			for subdir in results_dir.iterdir():
				if subdir.is_dir() and "blackbird" in subdir.name:
					json_file = subdir / f"{subdir.name}.json"
					if json_file.exists():
						# Check if the identifier is similar to the directory name
						dir_name = subdir.name.replace(f"_{date_raw}_blackbird", "")
						if (identifier.lower() in dir_name.lower() or 
							dir_name.lower() in identifier.lower() or
							any(var.lower() in dir_name.lower() for var in variations)):
							return json_file.read_text(encoding="utf-8")
	except Exception:
		pass
	
	return ""


async def stream_username(username: str):
	"""Run Blackbird for the provided username string and stream progress lines."""
	cmd = [
		sys.executable,
		str(BLACKBIRD_DIR / "blackbird.py"),
		"-u",
		str(username),
		"--json",
		"--timeout",
		str(BLACKBIRD_TIMEOUT),
		"--max-concurrent-requests",
		str(BLACKBIRD_MAX_CONCURRENT),
		"--no-update",
	]
	# Inherit current env and add safe console flags
	env = os.environ.copy()
	env.update({
		'PYTHONIOENCODING': 'utf-8',
		'TERM': 'dumb',
		'NO_COLOR': '1',
	})
	proc = await asyncio.create_subprocess_exec(
		*cmd, cwd=str(BLACKBIRD_DIR), stdout=PIPE, stderr=PIPE, env=env
	)
	# Stream stdout
	if proc.stdout:
		while True:
			line = await proc.stdout.readline()
			if not line:
				break
			yield line.decode("utf-8", errors="ignore").rstrip()
	await proc.wait()


async def stream_email(email: str):
	"""Run Blackbird for the provided email string and stream progress lines."""
	cmd = [
		sys.executable,
		str(BLACKBIRD_DIR / "blackbird.py"),
		"-e",
		str(email),
		"--json",
		"--timeout",
		str(BLACKBIRD_TIMEOUT),
		"--max-concurrent-requests",
		str(BLACKBIRD_MAX_CONCURRENT),
		"--no-update",
	]
	# Inherit current env and add safe console flags
	env = os.environ.copy()
	env.update({
		'PYTHONIOENCODING': 'utf-8',
		'TERM': 'dumb',
		'NO_COLOR': '1',
	})
	proc = await asyncio.create_subprocess_exec(
		*cmd, cwd=str(BLACKBIRD_DIR), stdout=PIPE, stderr=PIPE, env=env
	)
	# Stream stdout
	if proc.stdout:
		while True:
			line = await proc.stdout.readline()
			if not line:
				break
			yield line.decode("utf-8", errors="ignore").rstrip()
	await proc.wait()


def search_username(username: str) -> str:
	original = str(username)
	variants = [original]
	if " " in original:
		variants += [
			original.replace(" ", ""),
			original.replace(" ", "_"),
			original.replace(" ", "-"),
			original.replace(" ", "."),
		]

	results = []
	for ident in variants:
		print(f"DEBUG: Searching for username variant: '{ident}'")
		
		# Run Blackbird directly instead of using wrapper
		cmd = [
			sys.executable,
			str(BLACKBIRD_DIR / "blackbird.py"),
			"-u",
			ident,
			"--json",
			"--timeout",
			str(BLACKBIRD_TIMEOUT),
			"--max-concurrent-requests",
			str(BLACKBIRD_MAX_CONCURRENT),
			"--no-update"  # Skip update check to avoid console issues
		]
		
		print(f"DEBUG: Running command: {' '.join(cmd)}")
		print(f"DEBUG: Working directory: {BLACKBIRD_DIR}")
		
		try:
			# Set environment variables to help with console issues
			env = {
				'PYTHONIOENCODING': 'utf-8',
				'TERM': 'dumb',  # Use dumb terminal to avoid console issues
				'NO_COLOR': '1'  # Disable colors
			}
			
			# Run the command and wait for completion
			result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), shell=False, capture_output=True, text=True, timeout=180, env=env)
			
			print(f"DEBUG: Return code: {result.returncode}")
			print(f"DEBUG: Stdout length: {len(result.stdout)}")
			print(f"DEBUG: Stderr length: {len(result.stderr)}")
			
			if result.stderr:
				print(f"DEBUG: Stderr: {result.stderr[:200]}")
			
			# Wait a moment for file system to catch up
			import time
			time.sleep(5)
			
			# Try to read JSON output
			json_text = read_json_output(ident)
			print(f"DEBUG: JSON text length: {len(json_text)}")
			
			if json_text:
				print(f"DEBUG: Found JSON results for '{ident}'")
				results.append(json_text)
			elif result.stdout and len(result.stdout.strip()) > 10:
				print(f"DEBUG: Using stdout for '{ident}'")
				results.append(result.stdout)
			else:
				print(f"DEBUG: No results found for '{ident}'")
				
		except subprocess.TimeoutExpired:
			print(f"DEBUG: Timeout for '{ident}'")
		except Exception as e:
			print(f"DEBUG: Error for '{ident}': {e}")
	
	# If we found any results, try to merge JSON arrays from variants
	if results:
		print(f"DEBUG: Returning {len(results)} results")
		merged_items = []
		non_json_parts = []
		for part in results:
			try:
				data = json.loads(part)
				if isinstance(data, list):
					merged_items.extend(data)
				else:
					non_json_parts.append(part)
			except Exception:
				non_json_parts.append(part)
		if merged_items:
			try:
				return json.dumps(merged_items, ensure_ascii=False)
			except Exception:
				pass
		return "\n\n".join(non_json_parts)
	else:
		print("DEBUG: No results found for any variant")
		return ""


def scan_email(email: str) -> str:
	print(f"DEBUG: Scanning email: '{email}'")
	
	# Run Blackbird directly instead of using wrapper
	cmd = [
		sys.executable,
		str(BLACKBIRD_DIR / "blackbird.py"),
		"-e",
		str(email),
		"--json",
		"--timeout",
		str(BLACKBIRD_TIMEOUT),
		"--max-concurrent-requests",
		str(BLACKBIRD_MAX_CONCURRENT),
		"--no-update"  # Skip update check to avoid console issues
	]
	
	print(f"DEBUG: Running command: {' '.join(cmd)}")
	print(f"DEBUG: Working directory: {BLACKBIRD_DIR}")
	
	try:
		# Inherit environment and add safe console flags
		env = os.environ.copy()
		env.update({
			'PYTHONIOENCODING': 'utf-8',
			'TERM': 'dumb',  # Use dumb terminal to avoid console issues
			'NO_COLOR': '1',  # Disable colors
		})
		# Inherit environment and add safe console flags
		env = os.environ.copy()
		env.update({
			'PYTHONIOENCODING': 'utf-8',
			'TERM': 'dumb',  # Use dumb terminal to avoid console issues
			'NO_COLOR': '1',  # Disable colors
		})
		
		# Run the command and wait for completion
		result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), shell=False, capture_output=True, text=True, timeout=180, env=env)
		
		print(f"DEBUG: Return code: {result.returncode}")
		print(f"DEBUG: Stdout length: {len(result.stdout)}")
		print(f"DEBUG: Stderr length: {len(result.stderr)}")
		
		if result.stderr:
			print(f"DEBUG: Stderr: {result.stderr[:200]}")
		
		# Try to read JSON output first (guard against None)
		json_text = read_json_output(str(email)) or ""
		print(f"DEBUG: JSON text length: {len(json_text)}")
		
		if json_text:
			print("DEBUG: Found JSON results")
			return json_text
		
		# If no JSON found, check if there's any meaningful output
		output = result.stdout or result.stderr or ""
		
		# Filter out debug messages but keep meaningful content
		if output:
			lines = output.split('\n')
			filtered_lines = []
			for line in lines:
				line = line.strip()
				if (line and 
					not line.startswith('Using Python:') and 
					not line.startswith('🔄') and
					not line.startswith('✔️') and
					not line.startswith('🛰️') and
					not line.startswith('🏁') and
					not line.startswith('💾') and
					'Enumerating accounts' not in line and
					'Check completed' not in line and
					'Saved results' not in line):
					filtered_lines.append(line)
			
			output = '\n'.join(filtered_lines)
		
		# If still no meaningful output, provide a helpful message
		if not output or len(output.strip()) < 10:
			print("DEBUG: No meaningful output found")
			return f"No email accounts found for {email}. This email may not be registered on any of the platforms we check, or the email format might not be valid."
		
		print(f"DEBUG: Returning filtered output: {len(output)} characters")
		return output
		
	except subprocess.TimeoutExpired:
		print("DEBUG: Email scan timed out")
		return f"Email scan timed out for {email}. Please try again."
	except Exception as e:
		print(f"DEBUG: Email scan error: {e}")
		return f"Error scanning email {email}: {e}"
