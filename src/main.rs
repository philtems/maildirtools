use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::{self, Write, BufReader, BufRead};
use base64::engine::general_purpose;
use base64::Engine as _;
use encoding_rs;
use mailparse::{parse_mail, MailHeaderMap};
use regex::Regex;

struct EmailOptions {
    show_sender: bool,
    show_recipient: bool,
    show_subject: bool,
    show_cc: bool,
    show_smtp: bool,
    show_ip_only: bool,
    show_dkim: bool,
    bulk_mode: bool,
    save_attachments: Option<PathBuf>,
    show_text_body: bool,
    show_html_body: bool,
    input_file: String,
}

struct ConversionOptions {
    to_mbox: bool,
    to_maildir: bool,
    maildir_path: Option<PathBuf>,
    mbox_file: Option<PathBuf>,
}

impl EmailOptions {
    fn new() -> Self {
        EmailOptions {
            show_sender: false,
            show_recipient: false,
            show_subject: false,
            show_cc: false,
            show_smtp: false,
            show_ip_only: false,
            show_dkim: false,
            bulk_mode: false,
            save_attachments: None,
            show_text_body: false,
            show_html_body: false,
            input_file: String::new(),
        }
    }
}

impl ConversionOptions {
    fn new() -> Self {
        ConversionOptions {
            to_mbox: false,
            to_maildir: false,
            maildir_path: None,
            mbox_file: None,
        }
    }
}

fn decode_base64(encoded: &str) -> String {
    match general_purpose::STANDARD.decode(encoded.trim()) {
        Ok(decoded_bytes) => {
            // Try different encodings
            let (cow, _, had_errors) = encoding_rs::UTF_8.decode(&decoded_bytes);
            if had_errors {
                // Try WINDOWS-1252 if UTF-8 fails (more common than ISO-8859-1)
                let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(&decoded_bytes);
                cow.into_owned()
            } else {
                cow.into_owned()
            }
        }
        Err(_) => encoded.to_string(), // Return original if not valid base64
    }
}

fn decode_quoted_printable(input: &str) -> String {
    // Simplified quoted-printable decoding implementation
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '=' {
            let hex1 = chars.next();
            let hex2 = chars.next();
            
            if let (Some(h1), Some(h2)) = (hex1, hex2) {
                let hex_str = format!("{}{}", h1, h2);
                if hex_str.to_uppercase() == "0D" || hex_str.to_uppercase() == "0A" {
                    // Ignore encoded line breaks
                    continue;
                }
                if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                    result.push(byte as char);
                } else {
                    result.push('=');
                    result.push(h1);
                    result.push(h2);
                }
            } else {
                result.push('=');
                if let Some(h1) = hex1 {
                    result.push(h1);
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn extract_header_value(headers: &mailparse::headers::Headers, name: &str) -> Option<String> {
    headers.get_first_value(name).map(|value| {
        // Decode RFC 2047 encodings (e.g., =?UTF-8?B?...?=)
        if value.contains("=?") && value.contains("?=") {
            decode_rfc2047(&value)
        } else {
            value
        }
    })
}

fn decode_rfc2047(encoded: &str) -> String {
    let mut result = String::new();
    let mut current = encoded;
    
    while let Some(start) = current.find("=?") {
        // Add text before encoding
        result.push_str(&current[..start]);
        current = &current[start..];
        
        if let Some(end) = current.find("?=") {
            let encoded_part = &current[..end + 2];
            let parts: Vec<&str> = encoded_part.split('?').collect();
            
            if parts.len() >= 5 {
                let _charset = parts[1];
                let encoding = parts[2];
                let text = parts[3];
                
                match encoding.to_uppercase().as_str() {
                    "B" => {
                        // Base64
                        result.push_str(&decode_base64(text));
                    }
                    "Q" => {
                        // Quoted-printable
                        let text_with_underscores = text.replace('_', " ");
                        result.push_str(&decode_quoted_printable(&text_with_underscores));
                    }
                    _ => {
                        result.push_str(text);
                    }
                }
            } else {
                result.push_str(encoded_part);
            }
            
            current = &current[end + 2..];
        } else {
            result.push_str(current);
            current = "";
        }
    }
    
    result.push_str(current);
    result
}

fn extract_addresses(header_value: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    
    // Split by commas
    for part in header_value.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            // Extract email address (remove name)
            if let Some(start) = trimmed.find('<') {
                if let Some(end) = trimmed.find('>') {
                    addresses.push(trimmed[start + 1..end].trim().to_string());
                } else {
                    addresses.push(trimmed[start + 1..].trim().to_string());
                }
            } else {
                addresses.push(trimmed.to_string());
            }
        }
    }
    
    addresses
}

fn extract_ips_from_received(header_value: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let mut current = header_value;
    
    // Look for all IP addresses in brackets
    while let Some(start) = current.find('[') {
        if let Some(end) = current[start..].find(']') {
            let ip_candidate = &current[start + 1..start + end];
            
            // Check if it's a valid IP address
            if is_valid_ip(ip_candidate) && !ips.contains(&ip_candidate.to_string()) {
                ips.push(ip_candidate.to_string());
            }
            
            // Continue searching after this IP
            current = &current[start + end + 1..];
        } else {
            break;
        }
    }
    
    ips
}

fn is_valid_ip(ip: &str) -> bool {
    // Check if it's IPv4
    if is_valid_ipv4(ip) {
        return true;
    }
    
    // Check if it's IPv6
    if is_valid_ipv6(ip) {
        return true;
    }
    
    false
}

fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    
    for part in parts {
        if let Ok(num) = part.parse::<u8>() {
            // Check that the part is a number between 0 and 255
            let part_str = num.to_string();
            if part != part_str {
                // Avoid leading zeros like "001"
                return false;
            }
        } else {
            return false;
        }
    }
    
    true
}

fn is_valid_ipv6(ip: &str) -> bool {
    // Simplified IPv6 can contain ':' and hexadecimal digits
    if ip.contains(':') {
        let parts: Vec<&str> = ip.split(':').collect();
        
        // IPv6 has between 2 and 8 parts
        if parts.len() < 2 || parts.len() > 8 {
            return false;
        }
        
        // Each part must be hexadecimal
        for part in parts {
            if part.is_empty() {
                continue; // :: is allowed
            }
            if !part.chars().all(|c| c.is_digit(16)) {
                return false;
            }
        }
        
        return true;
    }
    
    false
}

fn check_dkim_status(headers: &mailparse::headers::Headers) -> String {
    // Check for DKIM-Signature header
    let dkim_signature = extract_header_value(headers, "DKIM-Signature");
    let authentication_results = extract_header_value(headers, "Authentication-Results");
    
    match (dkim_signature, authentication_results) {
        (Some(_), Some(results)) => {
            // Analyze authentication results
            let results_lower = results.to_lowercase();
            if results_lower.contains("dkim=pass") {
                "valid".to_string()
            } else if results_lower.contains("dkim=fail") {
                "invalid".to_string()
            } else if results_lower.contains("dkim=neutral") {
                "neutral".to_string()
            } else if results_lower.contains("dkim=temperror") {
                "temporary error".to_string()
            } else if results_lower.contains("dkim=permerror") {
                "permanent error".to_string()
            } else {
                "present (unknown status)".to_string()
            }
        }
        (Some(_), None) => {
            "present (unverified)".to_string()
        }
        (None, Some(results)) => {
            // No DKIM signature but authentication results exist
            if results.to_lowercase().contains("dkim=none") {
                "absent".to_string()
            } else {
                "DKIM information found".to_string()
            }
        }
        (None, None) => {
            "absent".to_string()
        }
    }
}

fn extract_dkim_domain(headers: &mailparse::headers::Headers) -> Option<String> {
    if let Some(dkim_sig) = extract_header_value(headers, "DKIM-Signature") {
        // Look for domain in DKIM signature
        // Typical format: d=example.com;
        for part in dkim_sig.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with("d=") {
                let domain = &trimmed[2..];
                // Remove quotes if present
                let clean_domain = domain.trim_matches('"').trim();
                if !clean_domain.is_empty() {
                    return Some(clean_domain.to_string());
                }
            }
        }
    }
    None
}

fn process_email(file_path: &str, options: &EmailOptions) -> io::Result<()> {
    let data = fs::read(file_path)?;
    let parsed = parse_mail(&data).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Email parsing error: {}", e))
    })?;
    
    let headers = parsed.get_headers();
    
    // Display sender
    if options.show_sender {
        if let Some(from) = extract_header_value(&headers, "From") {
            if options.bulk_mode {
                println!("{}", from);
            } else {
                println!("Sender: {}", from);
            }
        }
    }
    
    // Display recipient
    if options.show_recipient {
        if let Some(to) = extract_header_value(&headers, "To") {
            let addresses = extract_addresses(&to);
            if options.bulk_mode {
                for addr in &addresses {
                    println!("{}", addr);
                }
            } else {
                println!("Recipient(s): {}", addresses.join(", "));
            }
        }
    }
    
    // Display subject
    if options.show_subject {
        if let Some(subject) = extract_header_value(&headers, "Subject") {
            if options.bulk_mode {
                println!("{}", subject);
            } else {
                println!("Subject: {}", subject);
            }
        }
    }
    
    // Display CC recipients
    if options.show_cc {
        if let Some(cc) = extract_header_value(&headers, "Cc") {
            let addresses = extract_addresses(&cc);
            if !addresses.is_empty() {
                if options.bulk_mode {
                    for addr in &addresses {
                        println!("{}", addr);
                    }
                } else {
                    println!("Cc: {}", addresses.join(", "));
                }
            }
        }
        if let Some(bcc) = extract_header_value(&headers, "Bcc") {
            let addresses = extract_addresses(&bcc);
            if !addresses.is_empty() {
                if options.bulk_mode {
                    for addr in &addresses {
                        println!("{}", addr);
                    }
                } else {
                    println!("Bcc: {}", addresses.join(", "));
                }
            }
        }
    }
    
    // Display DKIM information
    if options.show_dkim {
        let dkim_status = check_dkim_status(&headers);
        let dkim_domain = extract_dkim_domain(&headers);
        
        if options.bulk_mode {
            println!("{}", dkim_status);
            if let Some(domain) = dkim_domain {
                println!("{}", domain);
            }
        } else {
            println!("DKIM: {}", dkim_status);
            if let Some(domain) = dkim_domain {
                println!("  Signed domain: {}", domain);
            }
        }
    }
    
    // Display SMTP transit servers
    if options.show_smtp {
        let received_values = headers.get_all_values("Received");
        if !received_values.is_empty() {
            if options.show_ip_only {
                // IP only mode - extract all unique IPs
                let mut all_ips = Vec::new();
                for recv in &received_values {
                    let ips = extract_ips_from_received(recv);
                    for ip in ips {
                        if !all_ips.contains(&ip) {
                            all_ips.push(ip);
                        }
                    }
                }
                
                if !all_ips.is_empty() {
                    if options.bulk_mode {
                        for ip in all_ips {
                            println!("{}", ip);
                        }
                    } else {
                        println!("SMTP server IP addresses:");
                        for ip in all_ips {
                            println!("  {}", ip);
                        }
                    }
                } else if !options.bulk_mode {
                    println!("No IP addresses found in Received headers.");
                }
            } else {
                // Normal mode with all details
                if !options.bulk_mode {
                    println!("SMTP transit servers:");
                }
                for recv in received_values {
                    if options.bulk_mode {
                        println!("{}", recv);
                    } else {
                        println!("  - {}", recv);
                    }
                }
            }
        } else if !options.bulk_mode && (options.show_smtp || options.show_ip_only) {
            println!("No Received headers found.");
        }
    }
    
    // Process attachments and message bodies
    process_parts(&parsed, options, 0)?;
    
    Ok(())
}

fn process_parts(part: &mailparse::ParsedMail, options: &EmailOptions, depth: usize) -> io::Result<()> {
    let content_type = part.ctype.mimetype.clone();
    
    // Check if it's an attachment
    let is_attachment = part
        .get_headers()
        .get_first_value("Content-Disposition")
        .map(|d| d.to_lowercase().contains("attachment"))
        .unwrap_or(false);
    
    if is_attachment && options.save_attachments.is_some() {
        save_attachment(part, options)?;
    } else {
        // Process message bodies
        if content_type.starts_with("text/") {
            let body = part.get_body_raw().unwrap_or_default();
            let body_str = String::from_utf8_lossy(&body);
            
            if content_type == "text/plain" && options.show_text_body {
                if options.bulk_mode {
                    println!("{}", decode_transfer_encoding(part, &body_str));
                } else {
                    println!("Text body:\n{}", decode_transfer_encoding(part, &body_str));
                }
            } else if content_type == "text/html" && options.show_html_body {
                if options.bulk_mode {
                    println!("{}", decode_transfer_encoding(part, &body_str));
                } else {
                    println!("HTML body:\n{}", decode_transfer_encoding(part, &body_str));
                }
            }
        } else if content_type.starts_with("multipart/") {
            for subpart in &part.subparts {
                process_parts(subpart, options, depth + 1)?;
            }
        }
    }
    
    Ok(())
}

fn decode_transfer_encoding(part: &mailparse::ParsedMail, body: &str) -> String {
    let encoding = part
        .get_headers()
        .get_first_value("Content-Transfer-Encoding")
        .unwrap_or_default()
        .to_lowercase();
    
    match encoding.as_str() {
        "base64" => decode_base64(body.trim()),
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_string(),
    }
}

fn save_attachment(part: &mailparse::ParsedMail, options: &EmailOptions) -> io::Result<()> {
    let save_path = options.save_attachments.as_ref().unwrap();
    
    // Create directory if it doesn't exist
    fs::create_dir_all(save_path)?;
    
    // Get filename
    let filename = part
        .get_headers()
        .get_first_value("Content-Disposition")
        .and_then(|cd| {
            let cd_lower = cd.to_lowercase();
            cd_lower.find("filename=")
                .map(|pos| {
                    let name_part = &cd_lower[pos + 9..];
                    extract_filename(name_part)
                })
        })
        .or_else(|| {
            part.get_headers()
                .get_first_value("Content-Type")
                .and_then(|ct| {
                    let ct_lower = ct.to_lowercase();
                    ct_lower.find("name=").map(|pos| {
                        let name_part = &ct_lower[pos + 5..];
                        extract_filename(name_part)
                    })
                })
        })
        .unwrap_or_else(|| "attachment.bin".to_string());
    
    let filepath = save_path.join(&filename);
    
    // Get and decode content
    let body = part.get_body_raw().unwrap_or_default();
    let decoded_body = decode_transfer_encoding(part, &String::from_utf8_lossy(&body));
    
    fs::write(&filepath, decoded_body)?;
    if !options.bulk_mode {
        println!("Attachment saved: {:?}", filepath);
    }
    
    Ok(())
}

fn extract_filename(input: &str) -> String {
    let input = input.trim();
    
    // Handle names in quotes
    if input.starts_with('"') && input.ends_with('"') && input.len() > 1 {
        return input[1..input.len() - 1].to_string();
    }
    
    // Handle names in apostrophes
    if input.starts_with('\'') && input.ends_with('\'') && input.len() > 1 {
        return input[1..input.len() - 1].to_string();
    }
    
    // Take up to first semicolon or space
    let end = input.find(';').unwrap_or_else(|| input.find(' ').unwrap_or(input.len()));
    input[..end].trim().to_string()
}

// ============== MAILDIR / MBOX CONVERSION UTILITIES ==============

fn convert_maildir_to_mbox(maildir_path: &Path, mbox_path: &Path) -> io::Result<()> {
    println!("Converting Maildir '{}' to mbox '{}'...", maildir_path.display(), mbox_path.display());
    
    // Look for emails in cur/, new/, and tmp/ directories
    let mut all_emails = Vec::new();
    
    for subdir in &["cur", "new", "tmp"] {
        let dir_path = maildir_path.join(subdir);
        if dir_path.exists() && dir_path.is_dir() {
            for entry in fs::read_dir(dir_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    all_emails.push(path);
                }
            }
        }
    }
    
    // Sort emails by modification time (oldest first) for better mbox ordering
    all_emails.sort_by(|a, b| {
        let a_meta = fs::metadata(a).unwrap();
        let b_meta = fs::metadata(b).unwrap();
        a_meta.modified().unwrap().cmp(&b_meta.modified().unwrap())
    });
    
    let email_count = all_emails.len();
    
    // Create or overwrite mbox file
    let mut mbox_file = fs::File::create(mbox_path)?;
    
    for email_path in &all_emails {
        let content = fs::read_to_string(email_path)?;
        
        // Write From_ line with timestamp
        let metadata = fs::metadata(email_path)?;
        let modified_time = metadata.modified().unwrap();
        
        // Convert to chrono DateTime
        let datetime: chrono::DateTime<chrono::Local> = modified_time.into();
        let from_line = format!("From MAILER-DAEMON {} \n", datetime.format("%a %b %d %H:%M:%S %Y"));
        mbox_file.write_all(from_line.as_bytes())?;
        
        // Write email content
        mbox_file.write_all(content.as_bytes())?;
        
        // Ensure proper separation with double newline
        mbox_file.write_all(b"\n")?;
    }
    
    println!("Conversion complete: {} emails converted to {}", email_count, mbox_path.display());
    Ok(())
}

fn convert_mbox_to_maildir(mbox_path: &Path, maildir_path: &Path) -> io::Result<()> {
    println!("Converting mbox '{}' to Maildir '{}'...", mbox_path.display(), maildir_path.display());
    
    // Create Maildir structure
    let cur_dir = maildir_path.join("cur");
    let new_dir = maildir_path.join("new");
    let tmp_dir = maildir_path.join("tmp");
    
    fs::create_dir_all(&cur_dir)?;
    fs::create_dir_all(&new_dir)?;
    fs::create_dir_all(&tmp_dir)?;
    
    // Open and read mbox file
    let file = fs::File::open(mbox_path)?;
    let reader = BufReader::new(file);
    
    let mut email_count = 0;
    let mut current_email = Vec::new();
    let mut in_email = false;
    
    // Regular expression to detect From_ line
    let from_regex = Regex::new(r"^From \S+ \w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}").unwrap();
    
    for line in reader.lines() {
        let line = line?;
        
        if from_regex.is_match(&line) && !in_email {
            // Start of a new email
            if !current_email.is_empty() {
                save_maildir_email(&current_email, &new_dir, email_count)?;
                email_count += 1;
                current_email.clear();
            }
            in_email = true;
        } else if in_email {
            current_email.push(line);
        }
    }
    
    // Save the last email
    if !current_email.is_empty() {
        save_maildir_email(&current_email, &new_dir, email_count)?;
        email_count += 1;
    }
    
    println!("Conversion complete: {} emails converted to {}", email_count, maildir_path.display());
    Ok(())
}

fn save_maildir_email(lines: &[String], new_dir: &Path, index: usize) -> io::Result<()> {
    use chrono::Local;
    
    // Use timestamp_nanos_opt() instead of deprecated timestamp_nanos()
    let timestamp = Local::now().timestamp_nanos_opt().unwrap_or(0);
    let filename = format!("{}.{}.maildirtools", timestamp, index);
    let filepath = new_dir.join(filename);
    
    let mut file = fs::File::create(filepath)?;
    for line in lines {
        writeln!(file, "{}", line)?;
    }
    
    Ok(())
}

fn print_help() {
    println!("MaildirTools - Email analysis and conversion utilities");
    println!("Copyright 2026 - Philippe TEMESI - https://www.tems.be");
    println!();
    println!("Usage for email analysis:");
    println!("  maildirtools <email_file> [options]");
    println!();
    println!("Analysis options:");
    println!("  -s              Show sender");
    println!("  -d              Show recipient");
    println!("  -subject        Show subject");
    println!("  -c              Show CC/BCC recipients");
    println!("  -smtp           Show SMTP transit servers");
    println!("  -ip             Show only IP addresses from SMTP servers (with -smtp)");
    println!("  -dkim           Show DKIM information (absent, valid, invalid)");
    println!("  -bulk           Bulk mode: display results without comments, one per line");
    println!("  -f <path>       Save attachments to the given path");
    println!("  -text           Show plain text body");
    println!("  -html           Show HTML body");
    println!();
    println!("Usage for Maildir/mbox conversion:");
    println!("  maildirtools --tombox --maildir <maildir_path> --mbox <mbox_file>");
    println!("  maildirtools --tomaildir --maildir <maildir_path> --mbox <mbox_file>");
    println!();
    println!("General options:");
    println!("  --help          Display this help");
    println!("  --version       Display version and information");
    println!();
    println!("Examples:");
    println!("  maildirtools email.eml -s -d -subject");
    println!("  maildirtools email.eml -smtp -ip");
    println!("  maildirtools email.eml -dkim -bulk");
    println!("  maildirtools --tombox --maildir ~/Maildir --mbox ~/backup.mbox");
    println!("  maildirtools --tomaildir --maildir ~/Maildir --mbox ~/archive.mbox");
}

fn print_version() {
    println!("MaildirTools v0.2.0");
    println!("Copyright 2026 - Philippe TEMESI");
    println!("https://www.tems.be");
    println!("License: Free for personal and professional use");
    println!();
    println!("Email analysis tool with support for:");
    println!("  - Metadata extraction (sender, recipient, subject, etc.)");
    println!("  - SMTP transit server and IP address analysis");
    println!("  - DKIM verification");
    println!("  - Base64 and Quoted-Printable decoding");
    println!("  - Attachment extraction");
    println!("  - Maildir to mbox conversion");
    println!("  - mbox to Maildir conversion");
}

fn parse_args() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        return Err("Insufficient arguments".to_string());
    }
    
    // Check for conversion mode
    if args.contains(&"--tombox".to_string()) || args.contains(&"--tomaildir".to_string()) {
        return parse_conversion_args(&args);
    }
    
    // Otherwise, parse email analysis mode
    parse_email_analysis_args(&args)
}

fn parse_conversion_args(args: &[String]) -> Result<(), String> {
    let mut options = ConversionOptions::new();
    let mut i = 1;
    
    while i < args.len() {
        match args[i].as_str() {
            "--tombox" => options.to_mbox = true,
            "--tomaildir" => options.to_maildir = true,
            "--maildir" => {
                i += 1;
                if i < args.len() {
                    options.maildir_path = Some(PathBuf::from(&args[i]));
                } else {
                    return Err("Missing path for --maildir option".to_string());
                }
            }
            "--mbox" => {
                i += 1;
                if i < args.len() {
                    options.mbox_file = Some(PathBuf::from(&args[i]));
                } else {
                    return Err("Missing path for --mbox option".to_string());
                }
            }
            "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--version" => {
                print_version();
                std::process::exit(0);
            }
            _ => {
                return Err(format!("Unknown option: {}", args[i]));
            }
        }
        i += 1;
    }
    
    // Validate conversion options
    if options.to_mbox && options.to_maildir {
        return Err("Cannot specify both --tombox and --tomaildir".to_string());
    }
    
    if !options.to_mbox && !options.to_maildir {
        return Err("Must specify either --tombox or --tomaildir".to_string());
    }
    
    if options.maildir_path.is_none() {
        return Err("Missing --maildir option".to_string());
    }
    
    if options.mbox_file.is_none() {
        return Err("Missing --mbox option".to_string());
    }
    
    // Perform conversion
    if let Err(e) = perform_conversion(&options) {
        eprintln!("Conversion error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}

fn perform_conversion(options: &ConversionOptions) -> io::Result<()> {
    let maildir_path = options.maildir_path.as_ref().unwrap();
    let mbox_path = options.mbox_file.as_ref().unwrap();
    
    if options.to_mbox {
        convert_maildir_to_mbox(maildir_path, mbox_path)?;
    } else if options.to_maildir {
        convert_mbox_to_maildir(mbox_path, maildir_path)?;
    }
    
    Ok(())
}

fn parse_email_analysis_args(args: &[String]) -> Result<(), String> {
    let mut options = EmailOptions::new();
    let mut i = 1;
    
    while i < args.len() {
        match args[i].as_str() {
            "-s" => options.show_sender = true,
            "-d" => options.show_recipient = true,
            "-subject" => options.show_subject = true,
            "-c" => options.show_cc = true,
            "-smtp" => options.show_smtp = true,
            "-ip" => options.show_ip_only = true,
            "-dkim" => options.show_dkim = true,
            "-bulk" => options.bulk_mode = true,
            "-text" => options.show_text_body = true,
            "-html" => options.show_html_body = true,
            "-f" => {
                i += 1;
                if i < args.len() {
                    options.save_attachments = Some(PathBuf::from(&args[i]));
                } else {
                    return Err("Missing path for -f option".to_string());
                }
            }
            "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--version" => {
                print_version();
                std::process::exit(0);
            }
            _ => {
                // If it's not an option, it's probably the input file
                if options.input_file.is_empty() && !args[i].starts_with('-') {
                    options.input_file = args[i].clone();
                } else {
                    return Err(format!("Unknown option: {}", args[i]));
                }
            }
        }
        i += 1;
    }
    
    if options.input_file.is_empty() {
        return Err("Input file not specified".to_string());
    }
    
    // If no options are specified, display everything
    if !options.show_sender && !options.show_recipient && !options.show_subject && 
       !options.show_cc && !options.show_smtp && !options.show_ip_only && 
       !options.show_dkim && options.save_attachments.is_none() && 
       !options.show_text_body && !options.show_html_body && !options.bulk_mode {
        options.show_sender = true;
        options.show_recipient = true;
        options.show_subject = true;
        options.show_text_body = true;
    }
    
    if let Err(e) = process_email(&options.input_file, &options) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}

fn main() {
    if let Err(e) = parse_args() {
        eprintln!("Error: {}", e);
        print_help();
        std::process::exit(1);
    }
}

