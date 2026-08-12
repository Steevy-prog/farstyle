// Minimal, dependency-free PDF writer.
//
// HTML→PDF on macOS has no reliable built-in CLI, and pulling a headless
// browser or a heavy crate just to print a report is overkill. PDF's text
// model is simple enough to emit directly: we lay the report out as monospaced
// text (Courier, one of the 14 standard fonts, so nothing needs embedding),
// paginate it, and write a valid PDF byte stream with a correct xref table.
//
// Input is plain text (the Markdown report renders fine as monospaced text).
// Non-ASCII is transliterated to ASCII so the WinAnsi base font stays valid.

const PAGE_W: f32 = 612.0;   // US Letter, points
const PAGE_H: f32 = 792.0;
const MARGIN: f32 = 54.0;    // 0.75"
const FONT_SIZE: f32 = 9.0;
const LEADING: f32 = 12.0;
const MAX_COLS: usize = 92;  // wrap width for Courier 9pt inside the margins
const TOP_Y: f32 = PAGE_H - MARGIN;

/// Render plain text into a PDF document (returned as raw bytes).
pub fn render_text_pdf(title: &str, body: &str) -> Vec<u8> {
    // 1. Compose the text: a title line, a rule, then the body.
    let mut raw = String::new();
    raw.push_str(title);
    raw.push('\n');
    raw.push_str(&"=".repeat(title.chars().count().min(MAX_COLS)));
    raw.push_str("\n\n");
    raw.push_str(body);

    // 2. Sanitize to ASCII and wrap into display lines.
    let lines = wrap_lines(&sanitize(&raw));

    // 3. Paginate.
    let rows_per_page = (((TOP_Y - MARGIN) / LEADING).floor() as usize).max(1);
    let pages: Vec<&[String]> = lines.chunks(rows_per_page).collect();
    let pages: Vec<&[String]> = if pages.is_empty() { vec![&[][..]] } else { pages };

    // 4. Object layout:
    //    1 = Catalog, 2 = Pages, 3 = Font,
    //    then per page p: page object = 4+2p, content object = 5+2p.
    let n_pages = pages.len();
    let mut objects: Vec<Vec<u8>> = Vec::new();

    // obj 1 — Catalog
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());

    // obj 2 — Pages (Kids filled below)
    let mut kids = String::new();
    for p in 0..n_pages {
        kids.push_str(&format!("{} 0 R ", 4 + 2 * p));
    }
    objects.push(format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids.trim(), n_pages).into_bytes());

    // obj 3 — Font (Courier, standard base-14, no embedding)
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".to_vec());

    // Per-page objects
    for (p, page) in pages.iter().enumerate() {
        let content_id = 5 + 2 * p;
        // Page object
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.0} {:.0}] \
             /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
            PAGE_W, PAGE_H, content_id
        ).into_bytes());
        // Content stream
        let stream = build_content_stream(page);
        let mut content_obj = Vec::new();
        content_obj.extend_from_slice(format!("<< /Length {} >>\nstream\n", stream.len()).as_bytes());
        content_obj.extend_from_slice(stream.as_bytes());
        content_obj.extend_from_slice(b"\nendstream");
        objects.push(content_obj);
    }

    // 5. Serialize with a byte-accurate xref table.
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    // Binary comment so tools treat the file as binary.
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

    let mut offsets: Vec<usize> = Vec::with_capacity(objects.len());
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(obj);
        out.extend_from_slice(b"\nendobj\n");
    }

    let xref_pos = out.len();
    let n_objs = objects.len() + 1; // +1 for the free object 0
    out.extend_from_slice(format!("xref\n0 {}\n", n_objs).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        out.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF",
                n_objs, xref_pos).as_bytes());
    out
}

fn build_content_stream(lines: &[String]) -> String {
    let mut s = String::new();
    s.push_str("BT\n");
    s.push_str(&format!("/F1 {:.0} Tf\n", FONT_SIZE));
    s.push_str(&format!("{:.0} TL\n", LEADING));
    s.push_str(&format!("{:.0} {:.0} Td\n", MARGIN, TOP_Y));
    for line in lines {
        s.push('(');
        s.push_str(&escape_pdf_string(line));
        s.push_str(") Tj\n");
        s.push_str("T*\n");
    }
    s.push_str("ET");
    s
}

fn escape_pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap on newlines and hard-wrap long lines at MAX_COLS, preserving blank lines.
fn wrap_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw_line in text.split('\n') {
        if raw_line.is_empty() {
            out.push(String::new());
            continue;
        }
        // Expand tabs so column math stays honest.
        let expanded = raw_line.replace('\t', "    ");
        let chars: Vec<char> = expanded.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let end = (i + MAX_COLS).min(chars.len());
            // Try to break on the last space in the window for tidiness.
            let mut brk = end;
            if end < chars.len() {
                if let Some(pos) = chars[i..end].iter().rposition(|&c| c == ' ') {
                    if pos > 0 { brk = i + pos; }
                }
            }
            out.push(chars[i..brk].iter().collect());
            i = if brk == i { end } else { brk };
            // Skip a single leading space carried over from the wrap point.
            if i < chars.len() && chars[i] == ' ' { i += 1; }
        }
    }
    out
}

/// Map non-ASCII (emoji, box-drawing, accents) to plain ASCII so the standard
/// WinAnsi Courier font renders every glyph.
fn sanitize(s: &str) -> String {
    s.chars().map(|c| match c {
        '\n' => '\n',
        c if (c as u32) < 128 => c,
        'é' | 'è' | 'ê' | 'ë' => 'e',
        'à' | 'â' | 'ä' => 'a',
        'ï' | 'î' => 'i',
        'ô' | 'ö' => 'o',
        'ù' | 'û' | 'ü' => 'u',
        'ç' => 'c',
        '–' | '—' | '─' | '━' => '-',
        '•' | '●' | '◦' => '*',
        '“' | '”' | '«' | '»' => '"',
        '‘' | '’' => '\'',
        _ => ' ',
    }).collect()
}
