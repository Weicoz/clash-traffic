//! Static HTML Report Generator for clash-traffic.

use crate::models::GroupRow;

pub fn format_bytes(bytes: i64) -> String {
    let b = bytes as f64;
    if b < 1024.0 {
        format!("{} B", bytes)
    } else if b < 1024.0 * 1024.0 {
        format!("{:.1} KiB", b / 1024.0)
    } else if b < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MiB", b / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB", b / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_duration(sec: f64) -> String {
    if sec < 60.0 {
        format!("{:.0}s", sec)
    } else if sec < 3600.0 {
        format!("{:.1}m", sec / 60.0)
    } else {
        format!("{:.1}h", sec / 3600.0)
    }
}

pub fn generate_html_report(rows: &[GroupRow], title: &str) -> String {
    let total_up: i64 = rows.iter().map(|r| r.up).sum();
    let total_down: i64 = rows.iter().map(|r| r.down).sum();
    let total_all = total_up + total_down;

    let mut tr_html = String::new();
    for r in rows {
        tr_html.push_str(&format!(
            "<tr>
                <td class='font-mono font-medium text-slate-800'>{}</td>
                <td class='text-slate-600'>{}</td>
                <td class='text-slate-600'>{}</td>
                <td><span class='px-2 py-0.5 text-xs rounded bg-slate-100 text-slate-700 font-mono'>{}</span></td>
                <td class='text-right font-mono text-slate-600'>{}</td>
                <td class='text-right font-mono text-slate-600'>{}</td>
                <td class='text-right font-mono font-semibold text-slate-800'>{}</td>
                <td class='text-right font-mono text-slate-500'>{}</td>
            </tr>\n",
            html_escape(&r.domain),
            html_escape(&r.rule),
            html_escape(&r.chain),
            html_escape(&r.protocol),
            format_bytes(r.up),
            format_bytes(r.down),
            format_bytes(r.total),
            format_duration(r.duration_sec)
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    </style>
</head>
<body class="bg-slate-50 text-slate-900 p-6 max-w-7xl mx-auto">
    <header class="mb-8 border-b pb-4">
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">{title}</h1>
        <p class="text-sm text-slate-500 mt-1">生成时间: {now_str} | 统计记录: {count} 行</p>
        <div class="mt-4 grid grid-cols-3 gap-4 max-w-lg">
            <div class="bg-white p-3 rounded-lg border shadow-sm">
                <div class="text-xs text-slate-500">总上传</div>
                <div class="text-lg font-bold font-mono text-blue-600">{fmt_up}</div>
            </div>
            <div class="bg-white p-3 rounded-lg border shadow-sm">
                <div class="text-xs text-slate-500">总下载</div>
                <div class="text-lg font-bold font-mono text-emerald-600">{fmt_down}</div>
            </div>
            <div class="bg-white p-3 rounded-lg border shadow-sm">
                <div class="text-xs text-slate-500">累计总量</div>
                <div class="text-lg font-bold font-mono text-slate-800">{fmt_total}</div>
            </div>
        </div>
    </header>

    <div class="bg-white rounded-xl shadow-sm border overflow-hidden">
        <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-50 border-b text-xs text-slate-500 uppercase tracking-wider">
                    <tr>
                        <th class="px-4 py-3">目标域名 / IP</th>
                        <th class="px-4 py-3">命中规则</th>
                        <th class="px-4 py-3">实际节点链</th>
                        <th class="px-4 py-3">协议</th>
                        <th class="px-4 py-3 text-right">上传</th>
                        <th class="px-4 py-3 text-right">下载</th>
                        <th class="px-4 py-3 text-right">累计流量</th>
                        <th class="px-4 py-3 text-right">时长</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-100">
                    {tr_html}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"#,
        title = html_escape(title),
        now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        count = rows.len(),
        fmt_up = format_bytes(total_up),
        fmt_down = format_bytes(total_down),
        fmt_total = format_bytes(total_all),
        tr_html = tr_html
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
