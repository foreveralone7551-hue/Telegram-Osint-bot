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
            "--no-update"
        ]
        
        try:
            env = os.environ.copy()
            env.update({
                'PYTHONIOENCODING': 'utf-8',
                'TERM': 'dumb',
                'NO_COLOR': '1'
            })
            
            result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), shell=False, capture_output=True, text=True, timeout=180, env=env)
            time.sleep(3) # Чуть уменьшили ожидание
            
            json_text = read_json_output(ident)
            
            if json_text:
                results.append(json_text)
            elif result.stdout:
                # ОЧИСТКА: убираем ANSI и оставляем ТОЛЬКО строки с ссылками
                clean_stdout = strip_ansi(result.stdout)
                valid_lines = []
                for line in clean_stdout.split('\n'):
                    line = line.strip()
                    # Берем только строки, где есть ссылка или маркер находки
                    if "http" in line or "[+]" in line or "Found" in line:
                        valid_lines.append(line)
                
                if valid_lines:
                    results.append("\n".join(valid_lines))
                elif "No accounts found" not in clean_stdout and len(clean_stdout.strip()) > 10:
                    # Если вообще ничего не нашли, пишем об этом
                    results.append(f"Search finished for {ident}. No clear links found.")
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: Timeout for '{ident}'")
        except Exception as e:
            print(f"DEBUG: Error for '{ident}': {e}")
    
    if results:
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
        return ""


def scan_email(email: str) -> str:
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
        "--no-update"
    ]
    
    try:
        env = os.environ.copy()
        env.update({
            'PYTHONIOENCODING': 'utf-8',
            'TERM': 'dumb',
            'NO_COLOR': '1',
        })
        
        result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), shell=False, capture_output=True, text=True, timeout=180, env=env)
        
        json_text = read_json_output(str(email)) or ""
        
        if json_text:
            return json_text
        
        # ОЧИСТКА для email
        output = result.stdout or result.stderr or ""
        output = strip_ansi(output)
        
        valid_lines = []
        for line in output.split('\n'):
            line = line.strip()
            if "http" in line or "[+]" in line or "Found" in line or "platform" in line.lower():
                valid_lines.append(line)
        
        if valid_lines:
            return "\n".join(valid_lines)
            
        return f"Scan complete for {email}. No public accounts found."
        
    except subprocess.TimeoutExpired:
        return f"Email scan timed out for {email}."
    except Exception as e:
        return f"Error scanning email {email}: {e}"
