//! 报表与实时表格渲染（与 Python 旧实现 src/clash_traffic/cli.py 的 report() / live_table() 行为等价）。
//!
//! 本模块只做渲染，不访问数据库与网络：
//! - render_report_html：生成 report.html（状态 JSON、分组表、明细表、前端筛选、5 秒自动刷新）。
//! - render_live_table：生成等宽终端看板（按终端宽度自适应列宽、CJK 双宽对齐、行尾页脚）。
//! - format_minutes / html_escape：与 Python f"{seconds / 60:.1f}" 与 html.escape 一致。
//!
//! 依赖仅限 std（不引入 chrono / serde / unicode-width 等外部 crate）；时间与状态文本由调用方传入。

use std::fmt::Write as _;

/// 报表页面顶部说明（与 Python report() 的文案逐字一致）。
const REPORT_NOTES: &str = "域名/应用/协议/规则/节点链排行只累计业务连接，排除 Inner 内部链路；内部传输另列入站类型表，不与业务流量相加。每秒只读采样，累计从首次启动开始；首次已存在连接的历史字节不计入。短连接及消失前最后一段流量可能漏计；核心总量与域名量口径可能不同，均不是机场账单。协议仅为核心 TCP/UDP 和入站类型，不解密 HTTPS/QUIC。结束时间是首次观察到消失的时间；时长是观察下界，并发连接时长相加不代表使用时间。同域名更换规则或节点链后分行累计；采样间路由切换的字节归属为近似值。核心未提供的信息显示未知。仅本地文件，不收集 URL/正文/凭据。";

/// 报表页面样式：深色主题、内联 CSS，不使用任何外部 CDN 或框架。
/// 末三条为本地增强：数字列右对齐、说明文字弱化、[hidden] 强制隐藏（前端筛选依赖它）。
const REPORT_CSS: &str = "body{font:15px system-ui;margin:28px;color:#ddd;background:#16191d}h1{font-size:24px}details{margin:24px 0}summary{font-size:19px;cursor:pointer}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:9px;border-bottom:1px solid #394049;text-align:left;overflow-wrap:anywhere}th{color:#8cd4ff}pre{white-space:pre-wrap}input{padding:10px;width:320px;background:#252a31;color:white;border:1px solid #586675}p{line-height:1.6;color:#abb9c5}.num{text-align:right;font-variant-numeric:tabular-nums}.meta{font-size:12px;color:#7f8b98;margin:6px 0 0}[hidden]{display:none!important}";

/// 原生筛选脚本：只按 textContent 过滤 tbody 行，不把任何数据拼进 HTML 字符串。
const REPORT_FILTER: &str = "document.querySelectorAll('tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(this.value.toLowerCase()))";

/// 调用方未给出标题时的兜底标题（等价于 Python 的 title 标签文案）。
const DEFAULT_TITLE: &str = "Clash Traffic 本地流量";

/// 终端表格：文本列最小宽度。
const MIN_TEXT_WIDTH: usize = 4;
/// 终端表格：动态列最大宽度（防止超长域名吃掉整行）。
const MAX_DYNAMIC_WIDTH: usize = 40;
/// 列分隔符，与 Python " | ".join 一致。
const COLUMN_SEPARATOR: &str = " | ";

/// 单张分组表的数据（调用方组织数据，本模块只渲染）。
pub struct ReportSection {
    /// details 的 summary 中显示的标题。
    pub summary: String,
    /// 表头；文本列与数字列由内容自动判定对齐方式。
    pub headers: Vec<String>,
    /// 数据行；行长度与 headers 不一致时按 headers 截断或补空。
    pub rows: Vec<Vec<String>>,
    /// 真实行数（rows 可能已被 LIMIT 截断，这里用于展示“共 N 行”）。
    pub row_count: usize,
}

/// 秒 → 分钟数值，保留一位小数，与 Python f"{seconds / 60:.1f}" 一致。
///
/// 返回值不含单位：报表“观察时长累计 / 分钟”列可直接使用；
/// 终端“时长”列由调用方追加 m（对齐 Python live_table 的 {:.1f}m）。
pub fn format_minutes(seconds: f64) -> String {
    let minutes = if seconds.is_finite() {
        seconds / 60.0
    } else {
        0.0
    };
    format!("{:.1}", minutes)
}

/// HTML 转义（与 Python html.escape 等价，单引号写成 &#x27;）。
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// 生成完整 HTML 报表：5 秒自动刷新 + 状态 JSON + 每张分组表 + 明细表 + 前端筛选 + 深色主题。
///
/// 结构照搬 Python report()：meta refresh 5 秒、pre 内嵌状态 JSON、
/// 每张分组表由 details open + summary 包裹、明细表由 details + summary 包裹。
/// 所有由数据派生的文本都经 html_escape；筛选脚本为静态脚本，只读 textContent。
pub fn render_report_html(
    sections: &[ReportSection],
    detail_headers: &[String],
    detail_rows: &[Vec<String>],
    status_json: &str,
    title: &str,
) -> String {
    let page_title = if title.trim().is_empty() {
        DEFAULT_TITLE
    } else {
        title
    };
    let heading = if page_title.ends_with("分布") {
        page_title.to_string()
    } else {
        format!("{}分布", page_title)
    };

    let mut html = String::with_capacity(16 * 1024 + status_json.len());
    html.push_str("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta http-equiv=\"refresh\" content=\"5\"><title>");
    html.push_str(&html_escape(page_title));
    html.push_str("</title><style>");
    html.push_str(REPORT_CSS);
    html.push_str("</style><h1>");
    html.push_str(&html_escape(&heading));
    html.push_str("</h1><p>");
    html.push_str(REPORT_NOTES);
    html.push_str("</p><input placeholder=\"筛选域名、规则、应用、节点链\" oninput=\"");
    html.push_str(REPORT_FILTER);
    html.push_str("\"><pre>");
    html.push_str(&html_escape(status_json));
    html.push_str("</pre>");

    for section in sections {
        render_section(&mut html, section);
    }
    render_detail(&mut html, detail_headers, detail_rows);

    html.push_str("</html>");
    html
}

/// 渲染单张分组表；headers 为空时只输出 details/summary，不生成空表。
fn render_section(out: &mut String, section: &ReportSection) {
    out.push_str("<details open><summary>");
    out.push_str(&html_escape(&section.summary));
    out.push_str("</summary>");
    if !section.headers.is_empty() {
        let numeric = numeric_columns(&section.headers, &section.rows);
        out.push_str("<table><thead><tr>");
        for (index, header) in section.headers.iter().enumerate() {
            push_cell(out, "th", header, numeric[index]);
        }
        out.push_str("</tr></thead><tbody>");
        for row in &section.rows {
            out.push_str("<tr>");
            for (index, flagged) in numeric.iter().enumerate() {
                let cell = row.get(index).map(String::as_str).unwrap_or("");
                push_cell(out, "td", cell, *flagged);
            }
            out.push_str("</tr>");
        }
        out.push_str("</tbody></table>");
    }
    // rows 可能已被调用方 LIMIT，用 row_count 报告真实行数。
    let _ = write!(out, "<p class=\"meta\">共 {} 行</p>", section.row_count);
    out.push_str("</details>");
}

/// 渲染最近连接明细表（Python 中为最近 500 行、13 列）。
fn render_detail(out: &mut String, headers: &[String], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }
    let numeric = numeric_columns(headers, rows);
    let _ = write!(
        out,
        "<details><summary>最近 {} 条连接（完整记录在 SQLite / CSV）</summary><table><thead><tr>",
        rows.len()
    );
    for (index, header) in headers.iter().enumerate() {
        push_cell(out, "th", header, numeric[index]);
    }
    out.push_str("</tr></thead><tbody>");
    for row in rows {
        out.push_str("<tr>");
        for (index, flagged) in numeric.iter().enumerate() {
            let cell = row.get(index).map(String::as_str).unwrap_or("");
            push_cell(out, "td", cell, *flagged);
        }
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table></details>");
}

/// 输出一个单元格：数字列加 class="num"（右对齐），文本列保持 Python 的裸标签。
fn push_cell(out: &mut String, tag: &str, value: &str, numeric: bool) {
    if numeric {
        let _ = write!(out, "<{} class=\"num\">", tag);
    } else {
        let _ = write!(out, "<{}>", tag);
    }
    out.push_str(&html_escape(value));
    let _ = write!(out, "</{}>", tag);
}

/// 判定每列是否数字列。
fn numeric_columns(headers: &[String], rows: &[Vec<String>]) -> Vec<bool> {
    (0..headers.len())
        .map(|index| is_numeric_column(rows, index))
        .collect()
}

/// 单列数字判定；空列视为文本列，避免表头被误判。
fn is_numeric_column(rows: &[Vec<String>], index: usize) -> bool {
    let mut seen = false;
    for row in rows {
        let cell = match row.get(index) {
            Some(value) => value.trim(),
            None => continue,
        };
        if cell.is_empty() || cell == "-" || cell == "—" {
            continue;
        }
        seen = true;
        if !looks_numeric(cell) {
            return false;
        }
    }
    seen
}

/// “12.34 / 1.00 KiB / 12.3s / 5.0m”这类值算数字；带冒号、路径、域名的值不算。
fn looks_numeric(value: &str) -> bool {
    let text = value.trim();
    if text.is_empty() {
        return false;
    }
    let unit_start = text
        .char_indices()
        .rev()
        .find(|(_, ch)| !ch.is_ascii_alphabetic())
        .map(|(index, ch)| index + ch.len_utf8());
    let (number, unit) = match unit_start {
        Some(index) => (&text[..index], &text[index..]),
        None => ("", text),
    };
    let unit_ok = matches!(
        unit,
        "" | "B" | "KiB" | "MiB" | "GiB" | "TiB" | "PiB" | "s" | "m" | "h"
    );
    unit_ok && is_plain_number(number.trim())
}

/// 纯数字判定：可选正负号，只允许 ASCII 数字与小数点，且至少一位数字。
fn is_plain_number(value: &str) -> bool {
    let body = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    !body.is_empty()
        && body.chars().any(|ch| ch.is_ascii_digit())
        && body.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
}

/// 终端实时表格：等宽字符对齐、按 width 自适应列宽、行尾页脚；返回可直接 print 的多行字符串。
///
/// 列宽规则与 Python live_table() 一致（域名 12..26、规则 12..28、链不小于 16，
/// 其余固定 6/10/10/10/9）；列数不为 8 时按内容自适应并收缩到终端宽度内。
/// 超长文本用 ... 截断，CJK 字符按 2 列宽计算。
pub fn render_live_table(
    headers: &[String],
    rows: &[Vec<String>],
    footer: &str,
    width: usize,
) -> String {
    let widths = live_column_widths(headers, rows, width);
    let numeric: Vec<bool> = (0..widths.len())
        .map(|index| is_numeric_column(rows, index))
        .collect();

    let mut lines: Vec<String> = Vec::with_capacity(rows.len() + 2);
    if !headers.is_empty() {
        lines.push(join_live_row(headers, &widths, &numeric));
    }
    for row in rows {
        lines.push(join_live_row(row, &widths, &numeric));
    }
    if !footer.is_empty() {
        lines.push(footer.to_string());
    }
    lines.join("\n")
}

/// 是否需要对整屏清屏重绘：TTY 返回 "\x1b[H\x1b[2J"，否则空串（与 Python display_live 一致）。
pub fn clear_screen_sequence() -> &'static str {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        "\x1b[H\x1b[2J"
    } else {
        ""
    }
}

/// 计算终端列宽；8 列时严格照搬 Python 公式，其余列数按内容自适应。
fn live_column_widths(headers: &[String], rows: &[Vec<String>], width: usize) -> Vec<usize> {
    let count = headers
        .len()
        .max(rows.iter().map(Vec::len).max().unwrap_or(0));
    if count == 0 {
        return Vec::new();
    }
    if count == 8 {
        let base = (width as i64 - 76).div_euclid(3);
        let domain = base.clamp(12, 26) as usize;
        let rule = base.clamp(12, 28) as usize;
        let chain = (width as i64 - domain as i64 - rule as i64 - 70).max(16) as usize;
        return vec![domain, rule, chain, 6, 10, 10, 10, 9];
    }
    let mut widths: Vec<usize> = (0..count)
        .map(|index| {
            let head = headers.get(index).map(|h| display_width(h)).unwrap_or(0);
            let body = rows
                .iter()
                .map(|row| row.get(index).map(|c| display_width(c)).unwrap_or(0))
                .max()
                .unwrap_or(0);
            head.max(body).clamp(MIN_TEXT_WIDTH, MAX_DYNAMIC_WIDTH)
        })
        .collect();
    let separators = COLUMN_SEPARATOR.len() * count.saturating_sub(1);
    let budget = width.saturating_sub(separators);
    let floor = if budget >= MIN_TEXT_WIDTH * count {
        MIN_TEXT_WIDTH
    } else {
        1
    };
    while widths.iter().sum::<usize>() > budget {
        let mut widest = floor;
        let mut target = None;
        for (index, value) in widths.iter().enumerate() {
            if *value > widest {
                widest = *value;
                target = Some(index);
            }
        }
        match target {
            Some(index) => widths[index] -= 1,
            None => break,
        }
    }
    widths
}

/// 拼一行：逐列按宽度填充，列间用 " | " 连接；行长度不足补空、超长截断。
fn join_live_row(values: &[String], widths: &[usize], numeric: &[bool]) -> String {
    let mut out = String::new();
    for (index, width) in widths.iter().enumerate() {
        if index > 0 {
            out.push_str(COLUMN_SEPARATOR);
        }
        let value = values.get(index).map(String::as_str).unwrap_or("");
        let align_right = numeric.get(index).copied().unwrap_or(false);
        out.push_str(&fit_cell(value, *width, align_right));
    }
    out
}

/// 按显示宽度填充单元格；数字列右对齐（左补空格），文本列左对齐。
fn fit_cell(value: &str, width: usize, align_right: bool) -> String {
    let clean = sanitize(value);
    let text = truncate_display(&clean, width);
    let padding = width.saturating_sub(display_width(&text));
    let mut out = String::with_capacity(width);
    if align_right {
        for _ in 0..padding {
            out.push(' ');
        }
    }
    out.push_str(&text);
    if !align_right {
        for _ in 0..padding {
            out.push(' ');
        }
    }
    out
}

/// 截断到指定显示宽度；被截断时追加 "..."（宽度 3），保证列对齐不被破坏。
fn truncate_display(value: &str, width: usize) -> String {
    if display_width(value) <= width {
        return value.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let marker = if width >= 3 { "..." } else { "" };
    let keep = width - marker.len();
    let mut out = String::new();
    let mut used = 0usize;
    for ch in value.chars() {
        let amount = char_width(ch);
        if used + amount > keep {
            break;
        }
        out.push(ch);
        used += amount;
    }
    out.push_str(marker);
    out
}

/// 去掉控制字符，避免不可信核心元数据注入终端转义序列（等价 Python text() 的 Cc 过滤）。
fn sanitize(value: &str) -> String {
    value.chars().filter(|ch| !ch.is_control()).collect()
}

/// 字符串显示宽度：CJK / 全角按 2 列，其余按 1 列（近似 unicode-width，不引外部 crate）。
fn display_width(value: &str) -> usize {
    value.chars().map(char_width).sum()
}

/// 单字符显示宽度（East Asian Wide / Fullwidth 近似集合）。
fn char_width(ch: char) -> usize {
    let code = ch as u32;
    let wide = matches!(code,
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xA960..=0xA97F
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE10..=0xFE19
        | 0xFE30..=0xFE6F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x2FFFD
        | 0x30000..=0x3FFFD
    );
    if wide {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    fn row(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn format_minutes_keeps_one_decimal() {
        assert_eq!(format_minutes(0.0), "0.0");
        assert_eq!(format_minutes(60.0), "1.0");
        assert_eq!(format_minutes(92.4), "1.5");
        assert_eq!(format_minutes(150.0), "2.5");
        assert_eq!(format_minutes(f64::NAN), "0.0");
    }

    #[test]
    fn html_escape_escapes_markup() {
        assert_eq!(
            html_escape("<script>alert('x' & \"y\")</script>"),
            "&lt;script&gt;alert(&#x27;x&#x27; &amp; &quot;y&quot;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("普通文本"), "普通文本");
    }

    fn sample_sections() -> Vec<ReportSection> {
        vec![
            ReportSection {
                summary: "域名 / 未识别目标 IP".to_string(),
                headers: headers(&[
                    "域名 / IP",
                    "命中规则",
                    "实际节点链",
                    "协议",
                    "上传",
                    "下载",
                    "合计",
                    "连接数",
                    "观察时长累计 / 分钟",
                ]),
                rows: vec![row(&[
                    "example.com",
                    "DOMAIN-SUFFIX",
                    "香港 01",
                    "TCP",
                    "1.00 KiB",
                    "2.00 KiB",
                    "3.00 KiB",
                    "2",
                    "1.5",
                ])],
                row_count: 1,
            },
            ReportSection {
                summary: "空表".to_string(),
                headers: Vec::new(),
                rows: Vec::new(),
                row_count: 0,
            },
        ]
    }

    #[test]
    fn report_html_has_refresh_details_filter_and_status() {
        let sections = sample_sections();
        let detail_headers = headers(&[
            "目标",
            "协议/入站",
            "IP/端口",
            "应用",
            "命中规则",
            "节点链",
            "核心开始",
            "首次观察",
            "最后观察",
            "观察消失",
            "观察时长",
            "上传",
            "下载",
        ]);
        let detail_rows = vec![row(&[
            "a.example.com",
            "TCP / Tun",
            "1.2.3.4:443",
            "curl",
            "MATCH",
            "直连",
            "10-18 14:00:00",
            "10-18 14:00:00",
            "10-18 14:00:05",
            "10-18 14:00:05",
            "5.0s",
            "1.00 KiB",
            "2.00 KiB",
        ])];
        let html = render_report_html(
            &sections,
            &detail_headers,
            &detail_rows,
            "{\n  \"samples\": 3\n}",
            "Clash Traffic 本地流量",
        );

        assert!(html.contains("<meta http-equiv=\"refresh\" content=\"5\">"));
        assert!(html.contains("<details open><summary>域名 / 未识别目标 IP</summary>"));
        assert!(
            html.contains("<details><summary>最近 1 条连接（完整记录在 SQLite / CSV）</summary>")
        );
        assert!(html.contains("placeholder=\"筛选域名、规则、应用、节点链\""));
        assert!(html.contains("oninput=\"document.querySelectorAll('tbody tr')"));
        assert!(html.contains("<pre>{"));
        assert!(html.contains("<!doctype html><html lang=\"zh-CN\">"));
        assert!(html.contains("<title>Clash Traffic 本地流量</title>"));
        assert!(html.contains("<h1>Clash Traffic 本地流量分布</h1>"));
        assert!(html.ends_with("</html>"));
        assert!(html.contains("<td class=\"num\">1.00 KiB</td>"));
        assert!(html.contains("<td>example.com</td>"));
        assert!(html.contains("<p class=\"meta\">共 1 行</p>"));
        assert!(html.contains(
            "<details open><summary>空表</summary><p class=\"meta\">共 0 行</p></details>"
        ));
        assert!(!html.contains("<td class=\"num\">0.0s</td>"));
        assert!(html.contains("<td class=\"num\">5.0s</td>"));
    }

    #[test]
    fn report_html_escapes_untrusted_values() {
        let sections = vec![ReportSection {
            summary: "<i>标题</i>".to_string(),
            headers: headers(&["<b>列</b>", "域名"]),
            rows: vec![row(&[
                "<script>alert(1)</script>",
                "\"><img src=x onerror=alert(2)>",
            ])],
            row_count: 1,
        }];
        let html = render_report_html(
            &sections,
            &[],
            &[],
            "{\"error\":\"<script>x</script>\"}",
            "",
        );

        assert!(html.contains("&lt;i&gt;标题&lt;/i&gt;"));
        assert!(html.contains("&lt;b&gt;列&lt;/b&gt;"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;img src=x onerror=alert(2)&gt;"));
        assert!(html.contains("{&quot;error&quot;:&quot;&lt;script&gt;x&lt;/script&gt;&quot;}"));
        for raw in [
            "<script>alert(1)</script>",
            "<img src=x",
            "<b>列</b>",
            "<i>标题</i>",
        ] {
            assert!(!html.contains(raw), "未转义的原始输入泄漏：{raw}");
        }
        assert!(html.contains("<title>Clash Traffic 本地流量</title>"));
        assert!(html.contains("&quot;"));
    }

    #[test]
    fn report_html_empty_input_does_not_panic() {
        let html = render_report_html(&[], &[], &[], "", "报表");
        assert!(html.contains("<meta http-equiv=\"refresh\""));
        assert!(html.contains("<title>报表</title>"));
        assert!(!html.contains("<details"));
        assert!(html.ends_with("</html>"));
    }

    #[test]
    fn report_html_tolerates_ragged_rows() {
        let sections = vec![ReportSection {
            summary: "参差".to_string(),
            headers: headers(&["A", "B", "C"]),
            rows: vec![row(&["only-a"]), row(&["1", "2", "3", "4"]), Vec::new()],
            row_count: 3,
        }];
        let html = render_report_html(&sections, &[], &[], "{}", "t");
        assert!(html.contains("<td>only-a</td><td class=\"num\"></td><td class=\"num\"></td>"));
        assert!(html.contains("<td>1</td><td class=\"num\">2</td><td class=\"num\">3</td>"));
        assert!(html.contains("<tr><td></td><td class=\"num\"></td><td class=\"num\"></td></tr>"));
        assert!(!html.contains("4</td>"), "超长行应按表头截断");
    }

    fn live_rows() -> Vec<Vec<String>> {
        vec![
            row(&[
                "api.example.com",
                "DOMAIN-SUFFIX",
                "香港 01 → 日本 02",
                "TCP",
                "1.00 KiB",
                "2.00 KiB",
                "3.00 KiB",
                "1.5m",
            ]),
            row(&[
                "测试域名.example",
                "MATCH",
                "直连",
                "UDP",
                "0.00 B",
                "1023.99 KiB",
                "1023.99 KiB",
                "0.0m",
            ]),
        ]
    }

    fn live_headers() -> Vec<String> {
        headers(&[
            "域名 / IP",
            "命中规则",
            "实际节点链",
            "协议",
            "上传",
            "下载",
            "累计",
            "时长",
        ])
    }

    #[test]
    fn live_table_line_counts() {
        let head = live_headers();
        let table = render_live_table(&head, &live_rows(), "连接 1 · 样本 2", 140);
        assert_eq!(table.lines().count(), 4, "{table}");
        let empty_rows = render_live_table(&head, &[], "页脚", 140);
        assert_eq!(empty_rows.lines().count(), 2);
        let no_headers_no_rows = render_live_table(&[], &[], "", 140);
        assert!(no_headers_no_rows.is_empty());
        let footer_only = render_live_table(&[], &[], "仅有页脚", 140);
        assert_eq!(footer_only, "仅有页脚");
        let no_footer = render_live_table(&head, &live_rows(), "", 140);
        assert_eq!(no_footer.lines().count(), 3);
        assert!(!no_footer.ends_with('\n'));
    }

    #[test]
    fn live_table_aligns_cjk_and_ascii() {
        let head = live_headers();
        let table = render_live_table(&head, &live_rows(), "连接 1 · 样本 2", 140);
        let body: Vec<&str> = table.lines().filter(|l| !l.starts_with("连接 1")).collect();
        assert_eq!(body.len(), 3);
        let expected = display_width(body[0]);
        for line in &body {
            assert_eq!(display_width(line), expected, "行宽不一致：{line:?}");
        }
        assert_eq!(expected, 21 + 21 + 28 + 6 + 10 + 10 + 10 + 9 + 3 * 7);
        assert!(expected <= 140);
    }

    #[test]
    fn live_table_truncates_with_marker() {
        let head = live_headers();
        let long_cjk = "非常长的中文域名".repeat(6);
        let rows = vec![row(&[
            &long_cjk, "MATCH", "直连", "TCP", "1.00 KiB", "1.00 KiB", "2.00 KiB", "0.0m",
        ])];
        let table = render_live_table(&head, &rows, "f", 140);
        let line = table.lines().nth(1).unwrap();
        assert!(line.contains("..."), "超长单元格应带截断标记：{line:?}");
        assert_eq!(
            display_width(line),
            21 + 21 + 28 + 6 + 10 + 10 + 10 + 9 + 3 * 7
        );
        let first_cell = line.split(COLUMN_SEPARATOR).next().unwrap();
        assert_eq!(display_width(first_cell), 21);
    }

    #[test]
    fn live_table_survives_tiny_width_and_ragged_rows() {
        let head = live_headers();
        for width in [0usize, 1, 5, 20, 60, 76, 79] {
            let table = render_live_table(&head, &live_rows(), "f", width);
            assert_eq!(table.lines().count(), 4, "width={width}");
            for line in table.lines() {
                assert!(!line.is_empty(), "width={width} 出现空行");
            }
        }
        let ragged = vec![
            row(&["only", "two"]),
            row(&["1", "2", "3", "4", "5", "6", "7", "8", "9"]),
        ];
        let table = render_live_table(&head, &ragged, "", 140);
        assert_eq!(table.lines().count(), 3);
        assert!(table.lines().nth(1).unwrap().contains("only"));
    }

    #[test]
    fn live_table_dynamic_columns_and_right_alignment() {
        let head = headers(&["目标", "上传"]);
        // 第二行把数字列撑到 10 列宽，第一行才能观察到右对齐的左侧填充
        let rows = vec![
            row(&["api.example.com", "1.00 KiB"]),
            row(&["b.com", "1023.99 KiB"]),
        ];
        let table = render_live_table(&head, &rows, "", 60);
        let line = table.lines().nth(1).unwrap();
        let cells: Vec<&str> = line.split(COLUMN_SEPARATOR).collect();
        assert_eq!(cells.len(), 2);
        assert!(!cells[0].starts_with(' '), "文本列应左对齐：{line:?}");
        assert_eq!(cells[0].trim(), "api.example.com");
        assert!(cells[1].starts_with(' '), "数字列应右对齐：{line:?}");
        assert_eq!(cells[1].trim(), "1.00 KiB");
        assert_eq!(
            display_width(cells[0]) + 3 + display_width(cells[1]),
            display_width(line)
        );
    }

    #[test]
    fn live_table_strips_control_characters() {
        let head = headers(&["目标", "备注"]);
        let rows = vec![row(&["\x1b[31mred\x07", "\x1b[2J危险"])];
        let table = render_live_table(&head, &rows, "", 60);
        assert!(!table.contains('\x1b'));
        assert!(!table.contains('\x07'));
        assert!(table.contains("red"));
    }

    #[test]
    fn clear_screen_sequence_is_static_escape() {
        let sequence = clear_screen_sequence();
        assert!(sequence.is_empty() || sequence == "\x1b[H\x1b[2J");
    }

    #[test]
    fn numeric_detection_ignores_text_columns() {
        let head = headers(&["目标", "上传", "开始", "IP/端口"]);
        let rows = vec![row(&["a.com", "1.00 KiB", "10-18 14:00:05", "1.2.3.4:443"])];
        let numeric = numeric_columns(&head, &rows);
        assert_eq!(numeric, vec![false, true, false, false]);
        assert!(looks_numeric("12.3s"));
        assert!(looks_numeric("0.0m"));
        assert!(looks_numeric("-1.00 KiB"));
        assert!(!looks_numeric("TCP"));
        assert!(!looks_numeric(""));
    }
}
